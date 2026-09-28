<!-- archdoc
verified_at: bc1fe68595b69ae67d16676c0da16702c82287c3
covers: main.go config.go scanner.go rule.go rules.go launcher.go report.go rules_test.go scope_test.go launcher_test.go go.mod examples/sample.mcp.json testdata/scopes.synthetic.json testdata/projects-only.synthetic.json
-->
# mcpscan: architecture

## Purpose

A single-package Go CLI (`package main`, module `github.com/JeremiahTee/mcpscan`, `go 1.25.0`, one dependency `golang.org/x/sync`) that statically reads Claude Desktop / Claude Code style MCP configs (a JSON object with an `mcpServers` map, plus the per-project `projects.<path>.mcpServers` maps of `~/.claude.json`) and emits an explainable, scored risk report per server. It never launches a server; it looks at `command`, `args`, `env` and `url`, and reads (never runs) a launcher script the command points at.

## Flow

```
 argv (files | globs)
        |  expandPaths (filepath.Glob, de-dup)          main.go
        v
 Scanner.ScanFiles  -- errgroup, SetLimit(concurrency) scanner.go
        |  per path: LoadConfig -> *Config              config.go
        v
 Assess(source, cfg)                                    report.go
        |  cfg.Entries(): user scope + local scope       config.go
        |  group by name, merge identical definitions,
        |  SCOPE_DUPLICATE / SCOPE_SHADOW + warnings
        |  per definition: Evaluate(name, srv)          rule.go
        |     runs every registered Rule.Check          rules.go
        |     COMMAND reads the launcher script         launcher.go
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
| `config.go` | `Config` / `Project` / `Server` structs; scopes `user` (top-level `mcpServers`) and `local` (`projects.<path>.mcpServers`); `Entries` flattens both deterministically; `LoadConfig` errors only if no scope has a server; `IsRemote` = `URL != ""`. |
| `scanner.go` | `Scanner` with functional option `WithConcurrency` (default 8, floor 1); `ScanFiles` fan-out/fan-in, first error cancels the rest; `WorstBand`. |
| `rule.go` | `Severity` (Info/Low/Medium/High) and weights (0/10/20/40), `Finding`, `Rule`, the `registry`, `Register`, `Rules`, `Evaluate`. |
| `launcher.go` | Launcher-script inspection: `launcherScript` picks the script (non-launcher command, or first arg of sh/bash/zsh); `inspectLauncher` reads it (absolute or `~/`, regular file, <= 256 KiB, no NUL bytes) for a Keychain read and literal secrets. Never executes it. |
| `rules.go` | The concrete checks, registered in `init()`, plus helpers (`unpinnedPackage`, `lastPathElement`, `hasArg`, `hasArgValue`). |
| `report.go` | `ServerReport` (with `Origins`) / `Report` (with `Warnings`), `score`, `band`, `Assess` (scope grouping, `scopeFindings`), text renderer `WriteText` (warnings, `from:` line only when a local scope exists, GOOD findings always shown). |
| `rules_test.go` | 7 unit tests: six rule cases via `Evaluate`, plus `score`/`band`. |
| `scope_test.go` | 8 tests: project-scoped loading, origins, merge, shadow warning, cross-project non-collision, text output. |
| `launcher_test.go` | 6 tests: Keychain launcher, literal secret (value never in output), token shape, plain script, bash arg, missing path. Scripts written to `t.TempDir()`. |
| `testdata/*.synthetic.json` | Synthetic scope fixtures (fake `/fake/...` paths, no real values). |
| `examples/sample.mcp.json` | Six-server sample config that trips most rules (contains a placeholder token value, not a real secret). |

## Rules

Six rules are registered in `rules.go` `init()`; they emit thirteen finding ids.

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

Assess also adds, outside the registry: `SCOPE_DUPLICATE` (Info) when one identical definition sits in user and local scope, and `SCOPE_SHADOW` (Low) when a local definition differs from the user one of the same name (Claude Code resolves local > project > user silently). Both add a report-level warning. The same name in two different projects is not a collision.

Scoring: bands are `critical` >= 60, `high` >= 40, `medium` >= 20, `low` > 0, else `clean`.

## How to run and test

`go test`, `go vet` and `go run .` were run on 2026-09-28 (branch `overnight/project-scope`).

```bash
cd ~/Desktop/repos/mcpscan
go test ./...                              # 21 tests (rules, scope, launcher)
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
- There are no tests for `main.go` or `scanner.go` (concurrency, cancellation); `WriteText` is covered only by the scope tests.
- `.mcp.json` (project scope) is not merged with `~/.claude.json`; pass it as a separate path. Shadowing between `.mcp.json` and the other scopes is not detected.
- Launcher inspection reads only the script the config names; a script that sources another file is not followed.
- The analysis is static only: it never sees runtime behaviour or real permission scopes (the README's own Limitations section says so).
