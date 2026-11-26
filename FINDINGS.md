# What we found scanning the 2,000 top-starred Go modules

This is the research behind `gomod-audit`: a real scan of the top of the Go ecosystem, run with
this exact engine. It was calibrated on one set and then frozen and run **once** on a disjoint
held-out set, so the numbers below were measured before any of them was reported. The method is
the same as [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md),
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md) and
[crate-audit](https://github.com/eltociear/crate-audit/blob/main/FINDINGS.md).

## Method

1. **Corpus.** Listed the 2,983 most-starred non-fork, non-archived Go repositories on GitHub
   (`gh api search/repositories?q=language:go`, sliced by star range, down to about 1,350 stars).
   Read each default branch's root `go.mod` in batches through the authenticated GraphQL API.
   That left 2,549 distinct module paths, including vanity paths such as `k8s.io/...`, `go.uber.org/...`
   and `golang.org/x/...`, plus `/vN` majors. 428 repositories had no root `go.mod` and 6 resolved to a module already listed.
2. **Fetch.** Resolved `@latest` on `proxy.golang.org` (with `!`-case-encoding), then read the module
   zip's central directory with HTTP Range requests and pulled only the `.go`, cgo C and `go.mod`
   entries. Source is about 20% of a module zip's bytes; the rest is assets, docs and testdata.
   Small zips were fetched whole. Everything was read into memory as text. Nothing was built,
   `go get`-ed or executed.
3. **What was scanned.** Importable code: every non-test `.go` file outside `testdata/` and `_`/`.`
   directories, plus C sources in cgo packages, capped at 24 MB of Go per module (17 of the largest
   monorepos were truncated). `_test.go` files were left out of the corpus run (`--no-tests`).
   `gomod-audit` demotes them anyway unless a test `init()` reaches HIGH.
4. **Calibration set:** ranks 1-1,200 by stars. **Held-out set:** ranks 1,201-2,000. Before the
   held-out run, the rules were frozen in commit `64d9d00`.
5. **Naive baseline:** every HIGH+/CRITICAL regex (plus the payload regexes) run on the raw text of
   the same files. No context, combinations, string-flow or import-time model. This is what a
   grep-style scanner reports.

Module paths that aren't on the proxy came back as errors (48 + 65; almost all 404/410, such as
`module ragflow` or private paths) and are excluded from the denominators. Scan date: 2026-11-27.

## Headline

| | Calibration (1,152 modules) | Held-out (735 modules) |
| --- | --- | --- |
| Naive context-free pass, HIGH+ | 59 (5.1%) | 26 (3.5%) |
| `gomod-audit`, first pass | 7 (0.6%) | **0 (0.0%)**, single blind run |
| `gomod-audit`, final (frozen rules) | **0** | **0** |
| MEDIUM (review hints, not alerts) | 13 | 5 |
| Not on the proxy (excluded) | 48 | 65 |

**The most-starred part of the Go ecosystem, as published right now, is clean by every
malicious-pattern rule here.** It's the expected result, and it's what makes the scanner usable:
a CRITICAL on a module you've never heard of only means something if the modules you already
depend on don't trip it. The held-out set was scanned once with frozen rules. It produced no HIGH+
finding, so nothing had to be fixed after it.

The 7 calibration first-pass hits were all false positives, each fixed by a context rule rather
than a per-module allowlist (see the noise table):

- a CLI's user-initiated "install X" command (`bash -c "curl … | bash"`) in a package `var` slice
- a public-DNS resolver table (`"1.0.0.1:53"`) in a package `var`
- a container runtime's C constructor that re-execs `/proc/self/exe` to enter a namespace
- a secret scanner's man page, which lists `trufflehog git …` invocations, and its detectors, which
  verify leaked keys against paste and file-drop APIs
- a pentest tool's `init()` storing an OAST domain as configuration
- a C2 framework's help table that mentions `wallet.dat` (a hashcat mode)
- a `--flag` default of a raw IP inside `init()`

## How much Go code runs at import time

| | Calibration | Held-out |
| --- | --- | --- |
| Modules with at least one non-test `func init()` | 888 (77%) | 492 (67%) |
| Total `init()` functions | 28,302 | 28,266 |
| Modules with a cgo package | 123 (10.7%) | 69 (9.4%) |
| Modules with `//go:generate` directives | 397 (34%) | 191 (26%) |
| Modules with OS/arch-gated files (`//go:build linux`, `_darwin.go`) | 552 (48%) | 252 (34%) |

Go has no install scripts, but **three in four popular modules run code the moment you import
them**. `init()` is overwhelmingly registration: codecs, drivers, flags, metrics, `sync.Once`
setup. What it almost never does:

| At import time (init / var initialisers + what they call) | Calibration | Held-out |
| --- | --- | --- |
| Spawns a process (LOW) | 18 modules | 8 |
| Network call (MEDIUM) | 9 | 2 |
| Shell with a computed command | 0 | 0 |
| Reads a credential store, dumps the environment, or decodes and runs a payload | 0 | 0 |

Even the import-time process spawns are benign: `git --version` / `go env` detection, or the
`main()` of a dev tool reaching `exec`. The import-time network calls are local resolvers, a dev
CLI's update check, and unix sockets. **An `init()` that shells out with a computed command, or
that sends anything along with your environment or keys, is something none of the 1,887 popular
modules do.** That is the gap every Go canary below falls into.

## The noise: what looks dangerous in Go but isn't

| Signal | Naive hits | Why it's noise | What `gomod-audit` does |
| --- | --- | --- | --- |
| `curl … \| sh` text | 49 | Install hints in help text, `fmt.Println`, error messages; CLIs that install a tool **when the user asks** | String-only (never flows into `exec.Command`) → INFO. Plain literal handed to `exec` at runtime → MEDIUM. CRITICAL only when decoded/obfuscated, at import time, in `//go:generate`/cgo, or aimed at a raw IP / collector |
| Disk-wipe text (`rm -rf /`, `mkfs /dev/sdX`) | 13 | Disk/VM tooling, docs, safety checks that refuse these commands | Same string-flow rule |
| Collector hosts (paste, file.io, OAST, webhooks) | 16 | Secret scanners verifying keys, pentest tools, notification libraries using the **user's** token | Chat webhooks count only with a hard-coded token; others need data collection (credential / env / hostname) in the same function, or a send at import time |
| `wallet.dat`, browser `Login Data` | 6 | Hashcat mode tables, browser-cookie libraries | Needs a file read and network |
| Shell-rc / cron / LaunchAgents writes | 7 | Installers for completions and services | HIGH only from import-time code |
| Reverse-shell text (`/dev/tcp/…`) | 5 | Security tools' payload generators, docs | Needs `net.Dial` + a reader on the conn + `sh -c <received>` in one function, or exec flow |
| `InsecureSkipVerify: true` | 385 modules | Almost always a user option | INFO |
| Credential-file references (`~/.kube/config`, `~/.aws`, `~/.ssh/id_*`) | 159 modules | Clients reading their own auth | INFO unless sent to a collector / raw IP, or read at import time next to a send |
| Raw-IP literals | 30 modules | Struct-tag examples, TEST-NET, public DNS resolvers, metadata endpoints | Documentation ranges and resolvers excluded; otherwise only at import time with a network call, or next to a credential read |

As in npm and Rust, **these are capabilities, not attacks.** Go adds two context dimensions of its
own that a grep misses:

1. **Where a string goes.** A pipe-to-shell is only dangerous if it reaches `exec.Command(sh, "-c", …)`.
   `gomod-audit` folds constants, concatenations and slice reassembly and follows the value into
   the call.
2. **When the function runs.** Package-level `var` initialisers and `init()` run on import.
   Func literals stored in a table don't run until they're called, so they're excluded. A string
   literal in a `var` table is data, not execution.

## What it does catch (the canaries)

These are inert reconstructions of public incidents and attack shapes, in `tests/fixtures/`.
Each fires at its expected severity:

| Canary | Shape | Result |
| --- | --- | --- |
| boltdb-go typosquat (2025 report: cached in the module proxy for ~3 years) | `init()` → goroutine → `net.Dial` to a C2 address reassembled by index → read a line → `sh -c` it → write the output back | CRITICAL `reverse_shell` |
| 2025 typosquat wave, Linux | `var X = f()`; `f` reassembles `wget -O - https://… \| /bin/bash &` from an 81-element 1-char `[]string` by index, gated on `runtime.GOOS == "linux"`, `.Start()`-ed detached | CRITICAL `download_execute` (decoded), `obfuscated_exec` at import |
| 2025 typosquat wave, macOS | Same loader as 18 string fragments in a `//go:build darwin` file | CRITICAL; the constraint is reported on the finding |
| 2025 disk wipers | `init()` base64-decodes `dd if=/dev/zero of=/dev/sda` and runs it with `bash -c` | CRITICAL `destructive` (decoded) |
| `init()` exfil | Reads `~/.ssh/id_rsa` and marshals `os.Environ()`, then `http.Post` to a collector | CRITICAL `credential_exfil` + `env_exfil` |
| Runtime credential theft | `~/.aws/credentials` → `webhook.site` | CRITICAL |
| Import-time dropper | `init()` → download → `chmod 0755` → exec | CRITICAL `dropper` |
| `//go:generate` | `sh -c "curl … \| sh"` | CRITICAL |
| cgo constructor | `__attribute__((constructor))` calling `system("curl … \| sh")` in the preamble | CRITICAL |

Ten benign controls stay below MEDIUM: CLI help text with install hints, a hook runner that runs
user commands through `sh -c`, SSH and AWS clients reading their own keys, `init()` registries and
`git --version` detection, malicious-looking strings in `_test.go` and `testdata/`, plain cgo, a
checksum-verified self-updater, `go:generate` running `protoc`, and a Telegram notifier using the
caller's token.

## What's worth flagging even in clean modules (18 MEDIUM, 34 LOW-only)

- **Runtime installers.** Five popular CLIs `exec` a literal `curl … | bash` to install a
  companion tool when the user asks. It isn't malicious, but it is remote code execution with no
  pinning, from inside a Go binary. MEDIUM is the right level.
- **Network at import time.** Resolver lookups and update checks reached from package
  initialisers. This mostly matters for libraries, because it makes `import` slow and
  non-hermetic.
- **`curl`/`wget` inside `//go:generate`.** Ten modules fetch over the network during code
  generation (LOW). Anyone who runs `go generate ./...` on a fresh clone executes it.
- **Two runtime dropper shapes without a checksum** (download → `chmod` → exec in an e2e helper and a dev tool's `main`), MEDIUM.

## Takeaways

1. **The checksum database is integrity, not safety.** `go.sum` and `sum.golang.org` guarantee
   that everyone gets the same backdoor, and the proxy keeps serving a version after the repo
   changes. Scan the version you lock: `gomod_audit.py --gosum go.sum`.
2. **Import is execution.** 77% of popular modules have `init()`. The import-time signals scored
   here (shell with a computed command, decoded payloads, sends with keys or env) are absent from
   all 1,887 modules scanned. In Go they're about as clear a signal as you get.
3. **Obfuscation is the tell.** Popular Go code doesn't reassemble shell commands from
   1-character string slices or 18-way string concatenation. When the reassembled command lands in
   `sh -c`, `gomod-audit` decodes it and scores what it says.
4. **Typosquats are the delivery mechanism.** Every public Go incident above imitated a popular
   path (`boltdb-go`, lookalike `github.com/<user>/…` forks). Check the module path before you scan
   it.

---

Reproduce: `scripts/bulk_scan.py` (resolve → scan, ≤4 workers, a child process with a timeout per
module).

*Findings are pattern matches that warrant human review, not verdicts. No module in the scanned
corpus is accused of anything. Report suspected malicious modules to the Go security team
(security@golang.org), not as unverified public accusations.*
