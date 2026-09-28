package main

import (
	"regexp"
	"strings"
)

// This file defines the concrete risk rules and registers them into the package
// registry (see rule.go). Each rule is small, single-purpose, and explainable —
// every finding it emits carries the reason it fired.

func init() {
	Register(Rule{ID: "SECRET_IN_ENV", Check: ruleSecretInEnv})
	Register(Rule{ID: "TRANSPORT", Check: ruleTransport})
	Register(Rule{ID: "COMMAND", Check: ruleCommand})
	Register(Rule{ID: "DOCKER", Check: ruleDocker})
	Register(Rule{ID: "FILESYSTEM", Check: ruleFilesystem})
	Register(Rule{ID: "DATA_SENSITIVE", Check: ruleDataSensitive})
}

var secretPattern = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key|pat)\b`)

var knownLaunchers = map[string]bool{
	"npx": true, "node": true, "python": true, "python3": true,
	"uv": true, "uvx": true, "docker": true, "deno": true, "bun": true,
}

var dataSensitiveServers = map[string]string{
	"github": "source code and repository access", "gitlab": "source code and repository access",
	"slack": "internal messages", "postgres": "database contents", "mysql": "database contents",
	"sqlite": "database contents", "filesystem": "local files", "gdrive": "cloud documents",
	"drive": "cloud documents", "notion": "internal documents", "jira": "internal tickets",
	"sentry": "production error data", "aws": "cloud infrastructure", "stripe": "payment data",
}

// ruleSecretInEnv: a credential handed to a subprocess widens the blast radius.
func ruleSecretInEnv(name string, s Server) []Finding {
	var out []Finding
	for k := range s.Env {
		if secretPattern.MatchString(k) {
			out = append(out, Finding{
				Rule: "SECRET_IN_ENV", Severity: High,
				Title:  "Credential exposed to server via environment",
				Detail: "Env var " + k + " looks like a secret. This server process can read it, widening the blast radius if the server (or a dependency it pulls) is compromised.",
			})
		}
	}
	return out
}

// ruleTransport: remote servers move data across the local trust boundary.
func ruleTransport(name string, s Server) []Finding {
	if !s.IsRemote() {
		return nil
	}
	out := []Finding{{
		Rule: "REMOTE_TRANSPORT", Severity: Medium,
		Title:  "Remote server over the network",
		Detail: "Reached at " + s.URL + ". Requests and any data they carry cross the local trust boundary to a third party; confirm the endpoint is owned and TLS-terminated.",
	}}
	if strings.HasPrefix(strings.ToLower(s.URL), "http://") {
		out = append(out, Finding{
			Rule: "INSECURE_TRANSPORT", Severity: High,
			Title:  "Cleartext HTTP endpoint",
			Detail: "The URL uses http:// rather than https://; traffic and tokens are sent unencrypted.",
		})
	}
	return out
}

// ruleCommand: flag arbitrary binaries, run-time remote code, and unpinned deps.
func ruleCommand(name string, s Server) []Finding {
	if s.IsRemote() || s.Command == "" {
		return nil
	}
	var out []Finding
	base := lastPathElement(s.Command)
	// A launcher script is read (never run): a Keychain-reading launcher is good
	// practice, not an unknown binary; any literal secret inside is still flagged.
	var li launcherInfo
	if script := launcherScript(s); script != "" {
		li, _ = inspectLauncher(script)
		out = append(out, li.findings...)
	}
	if !knownLaunchers[base] && !li.keychain {
		out = append(out, Finding{
			Rule: "ARBITRARY_BINARY", Severity: Medium,
			Title:  "Launches a non-standard executable",
			Detail: "Command " + s.Command + " is not a recognized launcher (npx/node/python/docker/...). Verify the binary's provenance before trusting it with tool access.",
		})
	}
	if base == "npx" && (hasArg(s.Args, "-y") || hasArg(s.Args, "--yes")) {
		out = append(out, Finding{
			Rule: "REMOTE_EXEC_ON_LAUNCH", Severity: Medium,
			Title:  "Fetches and runs a package at launch",
			Detail: "npx -y downloads and executes the package every start. A hijacked or typosquatted package name would run with this server's privileges.",
		})
	}
	if pkg, ok := unpinnedPackage(base, s.Args); ok {
		out = append(out, Finding{
			Rule: "UNPINNED_PACKAGE", Severity: Low,
			Title:  "Dependency is not version-pinned",
			Detail: "Package " + pkg + " has no explicit version (or uses @latest); the code that runs can change silently between launches.",
		})
	}
	return out
}

func ruleDocker(name string, s Server) []Finding {
	if lastPathElement(s.Command) != "docker" {
		return nil
	}
	var out []Finding
	if hasArg(s.Args, "--privileged") {
		out = append(out, Finding{
			Rule: "DOCKER_PRIVILEGED", Severity: High,
			Title:  "Container runs privileged",
			Detail: "--privileged grants near-host-level capabilities, defeating container isolation.",
		})
	}
	if hasArgValue(s.Args, "--network", "host") {
		out = append(out, Finding{
			Rule: "DOCKER_HOST_NETWORK", Severity: Medium,
			Title:  "Container shares the host network",
			Detail: "--network host removes network namespace isolation between the container and the host.",
		})
	}
	for i, a := range s.Args {
		if (a == "-v" || a == "--volume") && i+1 < len(s.Args) {
			m := s.Args[i+1]
			if m == "/" || strings.HasPrefix(m, "/:") || strings.HasPrefix(m, "/etc") || strings.HasPrefix(m, "/var/run/docker.sock") {
				out = append(out, Finding{
					Rule: "DOCKER_SENSITIVE_MOUNT", Severity: High,
					Title:  "Mounts a sensitive host path",
					Detail: "Bind mount " + m + " exposes host resources (or the Docker socket) into the container.",
				})
			}
		}
	}
	return out
}

func ruleFilesystem(name string, s Server) []Finding {
	lname := strings.ToLower(name)
	if !strings.Contains(lname, "filesystem") && !strings.Contains(lname, "files") {
		return nil
	}
	var dirs []string
	for _, a := range s.Args {
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") {
			dirs = append(dirs, a)
		}
	}
	for _, d := range dirs {
		if d == "/" || d == "~" || d == "~/" ||
			(strings.HasPrefix(d, "/Users") && strings.Count(d, "/") <= 2) ||
			(strings.HasPrefix(d, "/home") && strings.Count(d, "/") <= 2) {
			return []Finding{{
				Rule: "BROAD_FS_ACCESS", Severity: High,
				Title:  "Filesystem root is broad",
				Detail: "Allowed path " + d + " grants the agent read/write over an entire home or root tree. Narrow it to the specific project directories the workflow needs.",
			}}
		}
	}
	if len(dirs) > 4 {
		return []Finding{{
			Rule: "BROAD_FS_ACCESS", Severity: Medium,
			Title:  "Many filesystem roots granted",
			Detail: "This server is granted access to more than four directories; each is additional attack surface.",
		}}
	}
	return nil
}

func ruleDataSensitive(name string, s Server) []Finding {
	lname := strings.ToLower(name)
	for key, reason := range dataSensitiveServers {
		if strings.Contains(lname, key) {
			return []Finding{{
				Rule: "DATA_SENSITIVE", Severity: Low,
				Title:  "Touches sensitive data",
				Detail: "Name suggests access to " + reason + ". Scope its permissions to the minimum this workflow needs.",
			}}
		}
	}
	return nil
}

// --- shared helpers ---

func unpinnedPackage(base string, args []string) (string, bool) {
	if base != "npx" && base != "uvx" {
		return "", false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.HasSuffix(a, "@latest") {
			return a, true
		}
		if !strings.Contains(strings.TrimPrefix(a, "@"), "@") {
			return a, true
		}
		return "", false
	}
	return "", false
}

func lastPathElement(cmd string) string {
	if i := strings.LastIndexAny(cmd, "/\\"); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func hasArgValue(args []string, flag, val string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == val {
			return true
		}
	}
	return false
}
