<!-- archdoc
verified_at: 05af8767539e4fad0c3130b881eb33367b3b48ef
covers: main.go config.go scanner.go rule.go rules.go launcher.go project.go report.go rules_test.go scope_test.go launcher_test.go pin_test.go project_test.go go.mod examples/sample.mcp.json testdata/scopes.synthetic.json testdata/projects-only.synthetic.json
-->
# mcpscan: architecture

## Purpose

A single-package Go CLI (`package main`, module `github.com/JeremiahTee/mcpscan`, `go 1.25.0`, one dependency `golang.org/x/sync`) that statically reads Claude Desktop / Claude Code style MCP configs (a JSON object with an `mcpServers` map, plus the per-project `projects.<path>.mcpServers` maps of `~/.claude.json`, and optionally a repository's `.mcp.json` via `-project`) and emits an explainable, scored risk report per server. It never launches a server; it looks at `command`, `args`, `env` and `url`, and reads (never runs) a launcher script the command points at.

## Flow

```
 argv (files | globs)  [-project <repo>]
        |  expandPaths (filepath.Glob, de-dup)          main.go
        v
 Scanner.ScanFiles  -- errgroup, SetLimit(concurrency) scanner.go
        |  once: LoadProjectFile(<repo>/.mcp.json)       project.go
        |  per path: LoadConfig -> *Config; cfg.Repo     config.go
        v
 Assess(source, cfg)                                    report.go
        |  cfg.Entries(): user + project + local scope   config.go
        |  collisions(): per (name, project) winner      project.go
        |  group by name, merge identical definitions,
        |  SCOPE_DUPLICATE / SCOPE_SHADOW / SCOPE_SHADOWED + warnings
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
| `main.go` | Flags (`-json`, `-min-severity`, `-fail-on`, `-concurrency`, `-list-rules`, `-project`), glob expansion, output, exit codes (1 error, 2 no paths, 3 fail-on hit). |
| `config.go` | `Config` / `Project` / `Server` structs; scopes `user` (top-level `mcpServers`) and `local` (`projects.<path>.mcpServers`), plus `Config.Repo` (not from JSON) for `project`; `Entries` flattens user, project, local deterministically; `LoadConfig` errors only if no scope has a server; `IsRemote` = `URL != ""`. |
| `scanner.go` | `Scanner` with functional options `WithConcurrency` (default 8, floor 1) and `WithProjectRepo`; `ScanFiles` reads the `.mcp.json` once before the fan-out (shared read-only), fan-out/fan-in, first error cancels the rest; `WorstBand`. |
| `rule.go` | `Severity` (Info/Low/Medium/High) and weights (0/10/20/40), `Finding`, `Rule`, the `registry`, `Register`, `Rules`, `Evaluate`. |
| `launcher.go` | Launcher-script inspection: `launcherScript` picks the script (non-launcher command, or first arg of sh/bash/zsh); `inspectLauncher` reads it (absolute or `~/`, regular file, <= 256 KiB, no NUL bytes) for a Keychain read and literal secrets. Never executes it. |
| `project.go` | Project scope: `ScopeProject`, `ProjectFile`, `LoadProjectFile` (abs + symlink-resolved repo path, reads `<repo>/.mcp.json`), `WithProjectRepo`, `Collision`, `collisions` (per name and project context; user loads everywhere, local and project only in their path; winner by `scopeRank` local 3 > project 2 > user 1), `projectFindings`. |
| `rules.go` | The concrete checks, registered in `init()`, plus helpers (`unpinnedPackage` with `npmPinned` / `pythonPinned` / `firstPositional` / `flagValue`, `lastPathElement`, `hasArg`, `hasArgValue`). |
| `report.go` | `ServerReport` (with `Origins`) / `Report` (with `Warnings`, `Collisions`), `score`, `band`, `Assess` (scope grouping, `scopeFindings`), text renderer `WriteText` (warnings, `from:` line only when a non-user scope exists, GOOD findings always shown). |
| `rules_test.go` | 7 unit tests: six rule cases via `Evaluate`, plus `score`/`band`. |
| `scope_test.go` | 8 tests: project-scoped loading, origins, merge, shadow warning, cross-project non-collision, text output. |
| `pin_test.go` | 2 tests (25 table subtests): npx/uvx/`uv tool run` version pins, plus the fixture's `beta` uvx `==` pin. |
| `project_test.go` | 12 tests: `.mcp.json` loading, project vs user, local vs project, other-project non-collision, identical duplicate, no overlap, user-vs-local recorded, text output, Scanner option, JSON severity level. |
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
| | `UNPINNED_PACKAGE` (Low) | The package spec of `npx`, `uvx` or `uv tool run` (first positional, skipping values of known flags; for uv, `--from` wins) does not pin one exact version. npx: `name@1.2.3` (scope `@` ignored) pins; tags (`@latest`, `@next`) and ranges (`^`, `~`, `x`, `*`) do not. uv: `==` / `===` pin (extras allowed, `==1.*` does not), `name@1.2` pins, `>=`, `~=`, `<`, `!=` and a bare name do not. Docker images are not assessed. |
| `DOCKER` | `DOCKER_PRIVILEGED` (High) | `--privileged` in args. |
| | `DOCKER_HOST_NETWORK` (Medium) | `--network host` (as two separate args). |
| | `DOCKER_SENSITIVE_MOUNT` (High) | `-v`/`--volume` of `/`, `/etc*`, or `/var/run/docker.sock*`. |
| `FILESYSTEM` | `BROAD_FS_ACCESS` (High / Medium) | Server name contains `filesystem`/`files` and an arg is `/`, `~`, or a top-level `/Users/x` or `/home/x` (High); or more than four path args (Medium). |
| `DATA_SENSITIVE` | `DATA_SENSITIVE` (Low) | Server name contains a keyword such as github, slack, postgres, stripe, aws. |

Assess also adds, outside the registry: `SCOPE_DUPLICATE` (Info) when one identical definition sits in two scopes, `SCOPE_SHADOW` (Low) when a local or `.mcp.json` definition differs from the lower-precedence one it replaces, and `SCOPE_SHADOWED` (Info) when a `.mcp.json` definition never runs because a local one wins (Claude Code resolves local > project > user silently). Each adds a report-level warning; `-project` warnings name the winning scope. Every collision is also listed in `Report.Collisions` (JSON `collisions`: name, context, scopes highest first, winner, identical). The same name in two different projects is not a collision. Scope findings get their `Level` filled in `Assess`, since they are added after `Evaluate`.

Scoring: bands are `critical` >= 60, `high` >= 40, `medium` >= 20, `low` > 0, else `clean`.

## How to run and test

`go test`, `go vet` and `go run .` were run on 2026-09-28 (branch `overnight/project-scope`).

```bash
cd ~/Desktop/repos/mcpscan
go test ./...                              # 35 tests (rules, scope, launcher, pin, project)
go test -race ./...
go vet ./...
go build .                                 # binary ./mcpscan (gitignored)
go run . examples/sample.mcp.json
go run . -json examples/sample.mcp.json
go run . -fail-on high examples/sample.mcp.json; echo $?   # 3 when the band is reached
go run . -list-rules
go run . -project <repo> <config.json>    # .mcp.json collisions
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
- `.mcp.json` is compared only when `-project` is given, and the same repo is applied to every config in a fleet scan. Its path is matched to `projects.<path>` keys after `filepath.Abs` + `EvalSymlinks`; whether Claude Code writes those keys symlink-resolved is [UNVERIFIED].
- `SCOPE_DUPLICATE` and `SCOPE_SHADOWED` are Info, so text output hides them under the default `-min-severity low`; the warning lines always show.
- Docker image pinning (`image:tag` vs `image@sha256:`) is not assessed by `UNPINNED_PACKAGE`.
- `uvx --from pkg==1.2 cmd` checks only the `--from` spec; `--with` extras are not checked for pins.
- Launcher inspection reads only the script the config names; a script that sources another file is not followed.
- The analysis is static only: it never sees runtime behaviour or real permission scopes (the README's own Limitations section says so).
