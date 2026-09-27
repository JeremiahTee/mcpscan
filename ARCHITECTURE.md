<!-- archdoc
verified_at: PENDING
covers: main.go config.go scanner.go rule.go rules.go report.go rules_test.go go.mod examples/sample.mcp.json
-->
# mcpscan: architecture

## Purpose

A single-package Go CLI (`package main`, module `github.com/JeremiahTee/mcpscan`, `go 1.25.0`, one dependency `golang.org/x/sync`) that statically reads Claude Desktop / Claude Code style MCP configs (a JSON object with an `mcpServers` map) and emits an explainable, scored risk report per server. It never launches a server; it looks only at `command`, `args`, `env` and `url`.

## Flow

```
 argv (files | globs)
        |  expandPaths (filepath.Glob, de-dup)          main.go
        v
 Scanner.ScanFiles  -- errgroup, SetLimit(concurrency) scanner.go
        |  per path: LoadConfig -> *Config              config.go
        v
 Assess(source, cfg)                                    report.go
        |  per server: Evaluate(name, srv)              rule.go
        |     runs every registered Rule.Check          rules.go
        v
 findings -> score (sum of weights, cap 100) -> band    report.go
        |  servers sorted riskiest-first; overall = worst server
        v
 Report  --> WriteText (text, -min-severity filter)    report.go
         --> json.Encoder (-json)                       main.go
         --> WorstBand across reports -> -fail-on exit 3 scanner.go / main.go
```

## File | Job

| File | Job |
|---|---|
| `main.go` | Flags (`-json`, `-min-severity`, `-fail-on`, `-concurrency`, `-list-rules`), glob expansion, output, exit codes (1 error, 2 no paths, 3 fail-on hit). |
| `config.go` | `Config` / `Server` structs; `LoadConfig` reads + unmarshals, errors if `mcpServers` is empty; `IsRemote` = `URL != ""`. |
| `scanner.go` | `Scanner` with functional option `WithConcurrency` (default 8, floor 1); `ScanFiles` fan-out/fan-in, first error cancels the rest; `WorstBand`. |
| `rule.go` | `Severity` (Info/Low/Medium/High) and weights (0/10/20/40), `Finding`, `Rule`, the `registry`, `Register`, `Rules`, `Evaluate`. |
| `rules.go` | The concrete checks, registered in `init()`, plus helpers (`unpinnedPackage`, `lastPathElement`, `hasArg`, `hasArgValue`). |
| `report.go` | `ServerReport` / `Report`, `score`, `band`, `Assess`, text renderer `WriteText`. |
| `rules_test.go` | 7 unit tests: six rule cases via `Evaluate`, plus `score`/`band`. |
| `examples/sample.mcp.json` | Six-server sample config that trips most rules (contains a placeholder token value, not a real secret). |

## Rules

Six rules are registered in `rules.go` `init()`; they emit eleven finding ids.

| Registered rule | Finding id (severity) | Meaning |
|---|---|---|
| `SECRET_IN_ENV` | `SECRET_IN_ENV` (High) | An env var name matches the secret regex (token, secret, password, api key, access key, credential, private key, pat). |
| `TRANSPORT` | `REMOTE_TRANSPORT` (Medium) | Server has a `url`, so data crosses the local trust boundary. |
| | `INSECURE_TRANSPORT` (High) | That `url` starts with `http://`. |
| `COMMAND` | `ARBITRARY_BINARY` (Medium) | Command basename is not in the launcher list (npx, node, python, python3, uv, uvx, docker, deno, bun). |
| | `REMOTE_EXEC_ON_LAUNCH` (Medium) | `npx` with `-y` / `--yes`. |
| | `UNPINNED_PACKAGE` (Low) | First non-flag arg to `npx`/`uvx` has no `@version` or uses `@latest`. |
| `DOCKER` | `DOCKER_PRIVILEGED` (High) | `--privileged` in args. |
| | `DOCKER_HOST_NETWORK` (Medium) | `--network host` (as two separate args). |
| | `DOCKER_SENSITIVE_MOUNT` (High) | `-v`/`--volume` of `/`, `/etc*`, or `/var/run/docker.sock*`. |
| `FILESYSTEM` | `BROAD_FS_ACCESS` (High / Medium) | Server name contains `filesystem`/`files` and an arg is `/`, `~`, or a top-level `/Users/x` or `/home/x` (High); or more than four path args (Medium). |
| `DATA_SENSITIVE` | `DATA_SENSITIVE` (Low) | Server name contains a keyword such as github, slack, postgres, stripe, aws. |

Scoring: bands are `critical` >= 60, `high` >= 40, `medium` >= 20, `low` > 0, else `clean`.

## How to run and test

These commands were not run for this draft (the brief was read-only).

```bash
cd ~/Desktop/repos/mcpscan
go test ./...                              # the 7 tests in rules_test.go
go vet ./...
go build .                                 # binary ./mcpscan (gitignored)
go run . examples/sample.mcp.json
go run . -json examples/sample.mcp.json
go run . -fail-on high examples/sample.mcp.json; echo $?   # 3 when the band is reached
go run . -list-rules
```

## Known gaps

- `-list-rules` prints the six registry ids (`TRANSPORT`, `COMMAND`, `DOCKER`, `FILESYSTEM`...), but reports and the README table use the eleven finding ids. The two naming schemes don't match.
- `-fail-on` with a value outside `bandRank` maps to rank 0, so `bandAtLeast` is always true and any typo exits 3 (read from `main.go`; not executed).
- `filepath.Glob` has no `**` and Go doesn't expand `~`, so the README's `'~/.config/**/mcp.json'` example would likely match nothing and fall back to a literal path that doesn't exist [UNVERIFIED, not executed].
- One unreadable or malformed config aborts the whole fleet scan. No partial report is returned.
- `FILESYSTEM` and `DATA_SENSITIVE` key off the server's name, so a filesystem server under another name gets through.
- The secret regex ends in `\b`, so names like `ACCESS_TOKEN_ID` probably don't match (`_` is a word char) [UNVERIFIED, not tested].
- Findings with equal severity come out in map-iteration order (env keys, servers before the sort), so text output may differ between runs [UNVERIFIED].
- There are no tests for `main.go`, `scanner.go` (concurrency, cancellation) or `WriteText`.
- The analysis is static only: it never sees runtime behaviour or real permission scopes (the README's own Limitations section says so).
