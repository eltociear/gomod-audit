# Recall on real malicious Go modules (wave 5)

The canaries in `tests/fixtures` were written by us, shaped like the incidents. This file measures
the scanner on the **real modules**: the code that the Go module proxy actually served before it
blocked them. Everything was read statically: nothing was built, `go get`-ed or executed, and no
malware is stored in this repository. `recall/manifest.json` lists every artifact (module,
version, a sha256 over its files, report, severity before and after).

Scan date: 2026-11-27.

## Where the artifacts came from

`proxy.golang.org`, `goproxy.io` and the other mirrors now answer `SECURITY ERROR ... will not
serve it` for every reported module we tried (the 20 OSV `MAL-` Go entries plus the Socket 2025
lists), and the authors' GitHub repositories are gone. The real copies that survive:

| Source | What it holds | Used as |
| --- | --- | --- |
| [`dannolaius/go-malicious-masters`](https://github.com/dannolaius/go-malicious-masters) `RQ1/prev_packages` | 25 reported malicious module versions, as the proxy served them (thesis artifacts) | first pass + tuning |
| Software Heritage | `github.com/bpoorman/uid` at its malicious revision `e068190` (2023-05 visit) | held-out |
| GitHub | a still-live copy of a reported 2025 `hypert` typosquat, carrying a PowerShell reverse-shell variant of the loader | held-out (name withheld) |

Not obtainable: BufferZoneCorp (10 modules, 2026), gocommunity.io / gogets.dev (Graphalgo, 2026),
`utfave/cli` (2021), `v4n5haj/discord-mass-dm-go`. Their proxy copies are blocked, their repos are
deleted, and Software Heritage never archived them (or, for boltdb-go, archived only the rewritten
clean tag).

## Results

"HIGH+" means the module is flagged (exit code 2). 0.1.0 is the engine as published before this
work. Its rules were frozen (`64d9d00`) long before anyone looked at these artifacts, so its column
is a genuine blind measurement.

| Set | Modules | 0.1.0 HIGH+ | 0.1.0 MEDIUM+ | 0.2.0 HIGH+ | 0.2.0 MEDIUM+ |
| --- | --- | --- | --- | --- | --- |
| 2025 string-array / concat loaders, wipers (Socket: hypert, layout, gouid, mcp, ...) | 20 | 20 | 20 | 20 | 20 |
| boltdb-go/bolt v1.3.1 (C2 remote shell) | 1 | 0 | 0 | 1 | 1 |
| qiiniu/qmgo, qiniiu/qmgo v1.1.8 (fetch URL -> `sh -c`) | 2 | 0 | 0 | 2 | 2 |
| bpoorman/uuid (AES-encrypted data -> dpaste) | 1 | 0 | 0 | 1 | 1 |
| golang-random-ip-ssh-bruteforce (cracked logins -> author's Telegram bot) | 1 | 0 | 0 | 1 | 1 |
| **tuning set total** | **25** | **20 (80%)** | **20** | **25 (tuned)** | **25** |
| **held-out**, rules frozen in `7b0c7a5` | **2** | 1 | 1 | **2 / 2** | 2 |

The 0.2.0 tuning-set number is not a recall estimate: the rules were changed to catch those five.
The held-out pair is real but small and correlated. `bpoorman/uid` is the sibling of a tuned module,
and the live copy is a variant of a family the 0.1.0 rules already caught. Treat it as a smoke test,
not a rate.

## What the real artifacts taught (0.1.0 -> 0.2.0)

| Miss | What the real code does that the canary didn't | Rule change |
| --- | --- | --- |
| boltdb-go/bolt | **the whole file is tab-indented**, so every `^func` / `^var` anchored parse saw no functions at all. It dials via `net.Dialer{}` + `d.Dial("tcp", ...)` (not `net.Dial`), runs `exec.Command(args[0], args[1:]...)` (no shell), writes output back with `fmt.Fprintf(conn, ...)`. The IP is obfuscated as integers with digit substitution | de-indent files whose package clause is indented; `net.Dialer{}` / `.Dial("tcp", ..)` count as network; `reverse_shell` also fires on a non-literal program + conn read + output written back to the conn |
| qiiniu/qmgo | `script.Get(url).String()` (bitfield/script, not net/http) then `exec.Command("/bin/sh","-c", txt).Start()` inside `NewClient` (runtime, not `init`) | new `remote_script_exec`: a fetch of a hard-coded URL + `sh -c <computed>` in one function |
| bpoorman/uuid | posts to **dpaste.com** (not in the paste list) and AES-encrypts the loot first, so the "data collection" check found nothing | dpaste / paste.rs / rentry / termbin / 0x0.st / ix.io / ghostbin added; an exfil endpoint plus encryption before the send stays HIGH |
| ssh-bruteforce | hard-coded Telegram bot token, but what it sends is the brute-force results, not a local credential store | a chat webhook **with its token** that the same function sends to stays HIGH |

## Precision did not regress

Re-fetched benign sample: every third module of the original calibration + held-out ranking (ranks
1-2,000 of `modules.json`, the 2,983 most-starred Go repos, same method as FINDINGS.md), first 525
of those (510 resolved; 15 are no longer on the proxy), `@latest` re-resolved on 2026-11-27, importable code only. Both engines read the same
cached bytes.

| | 0.1.0 | 0.2.0 |
| --- | --- | --- |
| HIGH+ | 0 / 510 | **0 / 510** |
| MEDIUM | 4 | 4 |
| LOW | 10 | 11 |

The first 0.2.0 pass flagged one module HIGH: a DNS client's own `upgrade` subcommand fetches the
vendor's install script and runs it with `sh -c` (0 -> 1 HIGH+). `remote_script_exec` now drops to
LOW when the code is a command (`package main`) or wires the script to the user's terminal
(`Stdin/Stdout = os.Std*`). The qmgo shape, a library calling `.Start()` detached from inside
`NewClient`, stays HIGH. That fix came after the held-out run, and the held-out verdicts did not change
(re-checked). The table above is after the fix. An `ok-cmd-upgrade` control fixture pins it.

## Weaknesses this does not fix

- 20 of the 25 tuning modules are one actor's string-array loader. The scanner already caught that
  family, and the canaries were modelled on it.
- No real held-out artifact from an unseen campaign could be obtained. The 2026 campaigns
  (BufferZoneCorp credential stealer / CI poisoner, the Graphalgo RAT with an Ethereum dead drop
  and a Slack C2) are known only from reports, so recall on them is unmeasured.
- A payload hidden in a non-Go file (Graphalgo's ZIP disguised as `.sql`) is out of scope for a
  Go-source scanner.
