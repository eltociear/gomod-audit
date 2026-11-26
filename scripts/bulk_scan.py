#!/usr/bin/env python3
"""Reproduce the FINDINGS.md corpus run.

  1. enumerate   top-starred Go repos (gh api search, sliced by star range)   -> repos.json
     (done by a small gh loop; see FINDINGS.md - any ranked list of repos works)
  2. resolve     repo -> go.mod `module` path -> proxy.golang.org @latest     -> modules.json
  3. scan        each module zip is fetched INTO MEMORY and scanned in a child
                 process with a timeout (a C-level regex can't be interrupted)  -> results.jsonl

  python3 scripts/bulk_scan.py resolve repos.json modules.json
  python3 scripts/bulk_scan.py scan modules.json LO HI results.jsonl
  python3 scripts/bulk_scan.py one <module@version>          # child: prints one JSON line

The published run used GOMOD_AUDIT_SKIP_TESTS=1 GOMOD_AUDIT_MAX_TOTAL=24000000 (importable code only,
24 MB of Go per module) and GOMOD_AUDIT_CACHE=<dir> so the frozen-rules pass re-read the same sources.

Nothing is built, `go get`-ed or executed. <=4 concurrent workers, retry with backoff.
"""
import concurrent.futures as cf
import gzip
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.environ.get("GOMOD_AUDIT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import gomod_audit as ga  # noqa: E402

WORKERS = 4

# this network's IPv6 route is broken: resolve IPv4 only
import socket  # noqa: E402
socket.setdefaulttimeout(30)
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda host, port, family=0, *a, **k: _gai(host, port, socket.AF_INET, *a, **k)
TIMEOUT = 300


def _get(url, timeout=60, tries=4):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=ga.UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410) or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(3 * (i + 1))


def resolve_one(r):
    try:
        gm = _get("https://raw.githubusercontent.com/%s/%s/go.mod" % (r["repo"], r["branch"]), timeout=30).decode("utf-8", "replace")
    except Exception as e:
        return dict(r, error="no go.mod (%s)" % str(e)[:60])
    m = re.search(r"^module\s+\"?([^\s\"]+)", gm, re.M)
    if not m:
        return dict(r, error="no module line")
    mod = m.group(1)
    try:
        ver = ga.resolve_version(mod)
    except Exception as e:
        return dict(r, module=mod, error="proxy: %s" % str(e)[:60])
    return dict(r, module=mod, version=ver)


def _graphql_gomods(repos):
    """go.mod text for up to 50 repos in one authenticated `gh api graphql` call."""
    parts = []
    for i, r in enumerate(repos):
        o, n = r["repo"].split("/", 1)
        parts.append('r%d: repository(owner: %s, name: %s) { object(expression: "HEAD:go.mod") { ... on Blob { text } } }'
                     % (i, json.dumps(o), json.dumps(n)))
    q = "query {" + "\n".join(parts) + "}"
    for t in range(5):
        p = subprocess.run(["gh", "api", "graphql", "-f", "query=" + q], capture_output=True, text=True)
        try:
            data = json.loads(p.stdout).get("data") or {}
        except ValueError:
            data = {}
        if data:
            break
        time.sleep(10 * (t + 1))
    out = {}
    for i, r in enumerate(repos):
        node = data.get("r%d" % i) or {}
        out[r["repo"]] = ((node.get("object") or {}).get("text"))
    return out


def cmd_resolve(src, dst):
    """repo -> module path (from the go.mod on the default branch). Version is resolved at scan time (@latest)."""
    repos = json.load(open(src))
    seen, mods, miss = set(), [], 0
    for k in range(0, len(repos), 50):
        chunk = repos[k:k + 50]
        gm = _graphql_gomods(chunk)
        for r in chunk:
            m = re.search(r"^module\s+\"?([^\s\"]+)", gm.get(r["repo"]) or "", re.M)
            if not m:
                miss += 1
                continue
            if m.group(1) not in seen:
                seen.add(m.group(1))
                mods.append(dict(r, module=m.group(1), version="latest"))
        sys.stderr.write("resolved %d/%d -> %d modules\n" % (k + len(chunk), len(repos), len(mods)))
        sys.stderr.flush()
    json.dump(mods, open(dst, "w"), indent=0)
    print("%d repos -> %d modules (%d without a root go.mod)" % (len(repos), len(mods), miss))


NAIVE = [(pg["id"], re.compile(rx, re.M)) for sev in ("critical", "high", "medium") for pg in ga.PATTERNS[sev]
         for rx in pg["regexes"]] + [(pid, rx) for pid, rx in ga._PAYLOAD_RE]


def cmd_one(spec):
    mod, ver = ga.split_spec(spec)
    t0 = time.time()
    cache = os.environ.get("GOMOD_AUDIT_CACHE")  # optional: keep the sources so a re-scan needs no network
    cpath = os.path.join(cache, re.sub(r"[^\w.-]", "_", mod) + ".json.gz") if cache else None
    size = 0
    if cpath and os.path.exists(cpath):
        with gzip.open(cpath, "rt") as f:
            d = json.load(f)
        ver, files = d["version"], d["files"]
    elif cpath and os.path.exists(cpath[:-8] + ".zip") and os.path.exists(cpath[:-8] + ".zip.ver"):
        ver = open(cpath[:-8] + ".zip.ver").read().strip()
        files = {k: v for k, v in ga.files_from_zip(open(cpath[:-8] + ".zip", "rb").read()).items() if ga._wanted("m@v/" + k)}
    else:
        ver = ga.resolve_version(mod, ver)
        files = ga.module_files(mod, ver)
    if cpath and not os.path.exists(cpath):
        with gzip.open(cpath, "wt") as f:
            json.dump({"version": ver, "files": files}, f)
    if ga.SKIP_TESTS:
        files = {k: v for k, v in files.items() if not k.endswith("_test.go")}
    size = sum(len(v) for v in files.values())
    spec = "%s@%s" % (mod, ver)
    # context-free baseline: every HIGH+/MEDIUM regex on raw text of every file (tests, comments, strings)
    naive = set()
    for p, t in files.items():
        if p.endswith(ga.GO_EXT + ga.C_EXT):
            present = ga.needles_in(t)  # necessary-substring gate: same result, less CPU
            pay = any(n in t.lower() for n in ga.PAYLOAD_NEEDLES)
            for pid, rx in NAIVE:
                if pid in naive or (pid in ga.PAYLOAD and not pay) or not ga._has(t, pid, present):
                    continue
                if rx.search(t):
                    naive.add(pid)
    res = ga.scan_module(files, spec)
    imp_info = sorted({f["id"] for f in res["findings"] + res["info"] if f.get("context_kind") == "import"})
    print(json.dumps({"spec": spec, "src_bytes": size, "secs": round(time.time() - t0, 1),
                      "level": res["risk_level"], "stats": res["stats"],
                      "findings": [(f["severity"], f["id"], f["file"], f["line"], f["context"][:160], f["description"][:160])
                                   for f in res["findings"]],
                      "info_ids": sorted({f["id"] for f in res["info"]}), "import_ids": imp_info,
                      "naive": sorted(naive)}))


def cmd_scan(src, lo, hi, dst):
    mods = json.load(open(src))[int(lo):int(hi)]
    done = set()
    if os.path.exists(dst):
        for line in open(dst):
            try:
                done.add(json.loads(line)["spec"])
            except ValueError:
                pass
    done_mods = {d.split("@")[0] for d in done}
    lock = threading.Lock()

    def work(m):
        spec = "%s@%s" % (m["module"], m["version"])
        if spec in done or m["module"] in done_mods:
            return
        row = None
        for attempt in range(3):
            try:
                p = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "one", spec],
                                   capture_output=True, text=True, timeout=TIMEOUT)
                if p.returncode == 0 and p.stdout.strip():
                    row = json.loads(p.stdout.strip().splitlines()[-1])
                    break
                err = p.stderr.strip().splitlines()[-1][:200] if p.stderr.strip() else "rc=%d" % p.returncode
            except subprocess.TimeoutExpired:  # usually a stalled connection: retry
                err = "timeout"
            time.sleep(5 * (attempt + 1))
        if row is None:
            row = {"spec": spec, "error": err}
        row["repo"], row["stars"] = m["repo"], m["stars"]
        with lock:
            with open(dst, "a") as f:
                f.write(json.dumps(row) + "\n")
            sys.stderr.write("%s %s %s\n" % (row.get("level", "ERR"), spec, row.get("secs", row.get("error", ""))))

    with cf.ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(work, mods))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["resolve"]:
        cmd_resolve(a[1], a[2])
    elif a[:1] == ["scan"]:
        cmd_scan(*a[1:5])
    elif a[:1] == ["one"]:
        cmd_one(a[1])
    else:
        print(__doc__)
