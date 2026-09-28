# mcpscan

A small, explainable static risk scanner for **Model Context Protocol (MCP)** server configurations.

Agents are only as safe as the tools they can reach. `mcpscan` reads a Claude Desktop / Claude Code style config (`mcpServers`, including the per-project `projects.<path>.mcpServers` in `~/.claude.json`) and, for each connected server, flags where the agent's tool surface is **over-privileged or exposed** — then explains *why*, with a score you can audit rather than trust blindly.

```
$ mcpscan ~/Library/Application\ Support/Claude/claude_desktop_config.json

mcpscan — claude_desktop_config.json
overall risk: 80/100 (critical) across 6 server(s)

github  [stdio]  80/100 critical
  - HIGH   SECRET_IN_ENV          Credential exposed to server via environment
           Env var GITHUB_PERSONAL_ACCESS_TOKEN looks like a secret. This server
           process can read it, widening the blast radius if the server (or a
           dependency it pulls) is compromised.
  - MEDIUM REMOTE_EXEC_ON_LAUNCH  Fetches and runs a package at launch
           npx -y downloads and executes the package every start...
```

## Why

The MCP config is where an agent's real authority is granted — which subprocesses run, which credentials they see, which directories they can touch, which network endpoints they call. That authority is easy to over-grant and hard to eyeball. `mcpscan` turns a config into an **explainable risk report**: every point in the score traces back to a named rule and a plain-English reason.

## Install

```bash
go install github.com/JeremiahTee/mcpscan@latest
# or
git clone https://github.com/JeremiahTee/mcpscan && cd mcpscan && go build .
```

## Usage

```bash
mcpscan config.json                      # scan one config
mcpscan '~/.config/**/mcp.json' team/*   # globs; scan a whole fleet concurrently
mcpscan -json config.json                # machine-readable output
mcpscan -min-severity medium config.json # hide low/info noise
mcpscan -fail-on high config.json        # exit non-zero for CI gating
mcpscan -list-rules                      # list registered rules
mcpscan -project ~/code/app ~/.claude.json # compare a repo's .mcp.json against user + local scope
```

## What it checks

| Rule | Severity | What it flags |
|---|---|---|
| `SECRET_IN_ENV` | High | A credential (token/key/password) handed to a server subprocess |
| `BROAD_FS_ACCESS` | High | A filesystem server rooted at `/`, a home dir, or many directories |
| `DOCKER_SENSITIVE_MOUNT` | High | Bind-mounting the Docker socket or host system paths |
| `DOCKER_PRIVILEGED` | High | `--privileged` containers |
| `INSECURE_TRANSPORT` | High | A remote server reached over cleartext `http://` |
| `REMOTE_EXEC_ON_LAUNCH` | Medium | `npx -y` fetching and executing a package at every start |
| `DOCKER_HOST_NETWORK` | Medium | `--network host` removing network isolation |
| `SECRET_IN_LAUNCHER` | High | A literal credential inside the launcher script a server runs (value never printed) |
| `ARBITRARY_BINARY` | Medium | A non-standard launcher binary of unclear provenance |
| `REMOTE_TRANSPORT` | Medium | Any server reached across the network |
| `UNPINNED_PACKAGE` | Low | npx/uvx package without one exact version: no version, `@latest` or another tag, or a range (`>=`, `~=`, `^`). `pkg@1.2.3`, `@scope/pkg@1.2.3`, `pkg==1.2` and `--from pkg==1.2` count as pinned |
| `DATA_SENSITIVE` | Low | Server name implies access to sensitive data (github, postgres, slack…) |
| `SCOPE_SHADOW` | Low | A local-scope or `.mcp.json` server silently replaces a lower-precedence server of the same name |
| `SCOPE_DUPLICATE` | Info | The same definition is declared in more than one scope |
| `SCOPE_SHADOWED` | Info | A `.mcp.json` server never runs because a local-scope server of the same name wins |
| `KEYCHAIN_LAUNCHER` | Good | Launcher script reads its secret from the macOS Keychain at spawn (`security find-generic-password`): scored as good practice, not an unknown binary |

### Scopes

Claude Code keeps servers in `~/.claude.json` at two levels: top-level `mcpServers` (user scope) and `projects.<path>.mcpServers` (local scope, loaded only in that project). `mcpscan` scans both, labels each server with where it came from, reports an identical definition once, and warns when the same name exists in both scopes, because the client resolves names by precedence (local > project > user) and hides the loser without telling you.

Project scope lives in a repository's `.mcp.json`. Pass the repo with `-project <path>` and `mcpscan` reads `<path>/.mcp.json`, assesses its servers next to each config, and reports every name that is declared in more than one scope loading in that repo: user scope (everywhere), the `.mcp.json`, and the local scope stored under that repo's path. Each collision is labelled with its scopes in precedence order and the one that wins (text warning, and `collisions` in `-json`). A local server stored for a different project is not a collision.

The score is a capped sum of finding weights (High 40 / Medium 20 / Low 10), banded `clean → low → medium → high → critical`. A config is scored by its **worst** server — you're only as safe as your most-exposed connection.

## Design

Deliberately small and extensible:

- **Rule registry** — each rule is a `Rule{ID, Check}` that self-registers via `init()` (`rule.go` / `rules.go`). Adding a signal means adding a rule, not editing the engine (open/closed).
- **Concurrent, cancellable scanning** — multiple configs are assessed in parallel via a bounded `errgroup` with `context` cancellation; each goroutine writes only its own result slot, so no locking (`scanner.go`).
- **Functional options** — `NewScanner(WithConcurrency(n))` keeps the simple case simple.
- **Launcher inspection** — a script launcher is read as text (bounded, never executed) so a Keychain-at-spawn wrapper is recognised and a hard-coded secret in it is still caught (`launcher.go`).
- **`io.Writer`-based rendering** — text and JSON reporters share one report model (`report.go`).

## Limitations (read this)

`mcpscan` is a **static** analysis of the *config file only*. It cannot:

- see an agent's *runtime* tool invocations, actual permission scopes, or what a server does once launched;
- verify that a package or binary is *actually* malicious — it flags posture and provenance risk, not confirmed compromise;
- replace a real threat model. Findings are heuristics meant to focus human review, not a compliance verdict.

Treat the score as a prioritized to-do list for hardening, not a guarantee.

## License

MIT — see [LICENSE](LICENSE).
