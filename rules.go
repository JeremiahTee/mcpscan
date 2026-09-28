package main

import (
	"net/url"
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
		Detail: "Reached at " + sanitizeURL(s.URL) + ". Requests and any data they carry cross the local trust boundary to a third party; confirm the endpoint is owned and TLS-terminated.",
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
			Detail: "Package " + redactSpec(pkg) + " does not pin one exact version (no version, @latest or another tag, or a range such as >= or ^); the code that runs can change silently between launches.",
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

// unparseableURL stands in for a URL that cannot be split safely into parts.
const unparseableURL = "<unparseable URL>"

// sanitizeURL renders a URL for output without anything that may carry a
// credential: scheme, host (with port) and path are kept; userinfo is dropped;
// a query or fragment becomes <redacted>. A URL that does not parse, or whose
// "@" the parser did not read as userinfo (an unescaped # / ? or / in a
// password shifts it, and part of the secret would be taken as the host), is
// replaced whole: printing any part of it could print the secret.
func sanitizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return unparseableURL
	}
	if u.User == nil && strings.Contains(raw, "@") {
		return unparseableURL
	}
	out := u.Scheme + "://" + u.Host + u.EscapedPath()
	if u.RawQuery != "" || u.ForceQuery {
		out += "?<redacted>"
	}
	if u.Fragment != "" || u.RawFragment != "" || strings.HasSuffix(raw, "#") {
		out += "#<redacted>"
	}
	return out
}

// redactSpec sanitizes a URL embedded in a package spec (git+https://...,
// name @ https://...), keeping any text before the URL's scheme.
func redactSpec(spec string) string {
	i := strings.Index(spec, "://")
	if i < 0 {
		return spec
	}
	start := i
	for start > 0 && isSchemeChar(spec[start-1]) {
		start--
	}
	return spec[:start] + sanitizeURL(spec[start:])
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

// unpinnedPackage returns the package spec a launcher fetches when that spec
// does not pin one exact version. npx specs are name@version (the name may be
// @scope/name); uvx and `uv tool run` also accept pip-style specifiers, where
// only == and === pin; >=, ~=, <, != and a bare name are ranges. uvx --from
// names the package explicitly, so the positional arg is then only a command.
func unpinnedPackage(base string, args []string) (string, bool) {
	switch {
	case base == "npx":
		spec := firstPositional(args, npxValueFlags)
		if spec == "" || npmPinned(spec) {
			return "", false
		}
		return spec, true
	case base == "uv" && len(args) >= 2 && args[0] == "tool" && args[1] == "run":
		args = args[2:]
	case base == "uvx":
	default:
		return "", false
	}
	spec := flagValue(args, "--from")
	if spec == "" {
		spec = firstPositional(args, uvValueFlags)
	}
	if spec == "" || pythonPinned(spec) {
		return "", false
	}
	return spec, true
}

// Flags whose next arg is a value, not the package.
var (
	npxValueFlags = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true}
	uvValueFlags  = map[string]bool{
		"--from": true, "--with": true, "-w": true, "--with-requirements": true,
		"--with-editable": true, "--python": true, "-p": true, "--index": true,
		"--index-url": true, "--extra-index-url": true, "--default-index": true,
		"--constraints": true, "-c": true, "--overrides": true,
	}
)

// firstPositional returns the first arg that is neither a flag nor the value
// of a flag in valueFlags.
func firstPositional(args []string, valueFlags map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if valueFlags[a] {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

// flagValue returns the value of `flag v` or `flag=v`, or "".
func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, flag+"=") {
			return strings.TrimPrefix(a, flag+"=")
		}
	}
	return ""
}

// exactVersion is one concrete version: 1.2.3, v1.2, 1.2.3-beta.1, 1.2.3+build.
// Dist-tags (latest, next) and ranges (^1, ~1, 1.x, >=1) are not exact.
var exactVersion = regexp.MustCompile(`^v?\d+(\.\d+)*([-+.][0-9A-Za-z.-]+)?$`)

// npmPinned reports whether an npm spec carries an exact version after the
// name. A leading @ belongs to the scope, not to a version.
func npmPinned(spec string) bool {
	i := strings.LastIndex(spec, "@")
	if i <= 0 {
		return false
	}
	v := spec[i+1:]
	return !strings.ContainsAny(v, "xX*") && exactVersion.MatchString(v)
}

// pythonPinned reports whether a uv/pip spec pins one version: name==1.2,
// name===1.2, or uv's name@1.2. Extras ([cli]) are allowed before the pin.
func pythonPinned(spec string) bool {
	if i := strings.Index(spec, "=="); i > 0 {
		v := strings.TrimPrefix(spec[i+2:], "=")
		if strings.ContainsAny(v, ",;*") { // ==1.*, or a second specifier
			return false
		}
		return v != ""
	}
	if strings.ContainsAny(spec, "<>!~=") {
		return false
	}
	return npmPinned(spec)
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
