package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Launcher-script inspection. A common hardening pattern is to register a small
// shell script as the server command; the script reads credentials from the macOS
// Keychain at spawn (`security find-generic-password ... -w`) and execs the real
// server, so no secret sits in the MCP config. Without looking inside, that script
// is indistinguishable from an unknown binary. This file reads it (text only,
// bounded size, never executed) and reports what it finds. Findings name the
// variable and line, never the value.

// maxLauncherBytes bounds how much of a launcher is read; launchers are tiny.
const maxLauncherBytes = 256 << 10

// shellInterpreters run a script given as their first non-flag argument.
var shellInterpreters = map[string]bool{"sh": true, "bash": true, "zsh": true}

var keychainRead = regexp.MustCompile(`\bsecurity\s+find-(generic|internet)-password\b`)

var shellAssign = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

var secretName = regexp.MustCompile(`(?i)(token|secret|password|passwd|api_?key|access_?key|credential|private_?key)`)

// tokenShapes are formats that are a credential wherever they appear.
var tokenShapes = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})`)},
	{"Anthropic key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"OpenAI-style key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// launcherInfo is what inspecting a launcher script produced.
type launcherInfo struct {
	keychain bool
	findings []Finding
}

// launcherScript returns the script path a server launches, if any: the command
// itself when it is not a known launcher, or the first non-flag argument when the
// command is a shell interpreter.
func launcherScript(s Server) string {
	base := lastPathElement(s.Command)
	if shellInterpreters[base] {
		for _, a := range s.Args {
			if !strings.HasPrefix(a, "-") {
				return a
			}
		}
		return ""
	}
	if knownLaunchers[base] {
		return ""
	}
	return s.Command
}

// inspectLauncher reads a launcher script and reports whether it reads the
// Keychain and whether it holds a literal secret. ok is false when the path cannot
// be resolved, is not a regular file, is too large, or is binary; the caller then
// treats the command as unrecognised, as before.
func inspectLauncher(path string) (info launcherInfo, ok bool) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return info, false
		}
		path = filepath.Join(home, path[2:])
	}
	if !filepath.IsAbs(path) {
		return info, false
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxLauncherBytes {
		return info, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(raw, 0) >= 0 {
		return info, false
	}

	for i, line := range strings.Split(string(raw), "\n") {
		where := "line " + strconv.Itoa(i+1) + " of " + path
		trimmed := strings.TrimSpace(line)
		comment := strings.HasPrefix(trimmed, "#")
		if !comment && keychainRead.MatchString(line) {
			info.keychain = true
		}
		flagged := false
		for _, ts := range tokenShapes {
			if ts.re.MatchString(line) {
				info.findings = append(info.findings, Finding{
					Rule: "SECRET_IN_LAUNCHER", Severity: High,
					Title:  "Literal credential inside the launcher script",
					Detail: "A " + ts.kind + " appears in plaintext at " + where + ". Move it to the Keychain and read it at spawn; rotate it, since the file may have been copied or backed up.",
				})
				flagged = true
				break
			}
		}
		if flagged || comment {
			continue
		}
		if m := shellAssign.FindStringSubmatch(line); m != nil && secretName.MatchString(m[1]) && isLiteral(m[2]) {
			info.findings = append(info.findings, Finding{
				Rule: "SECRET_IN_LAUNCHER", Severity: High,
				Title:  "Literal credential inside the launcher script",
				Detail: "Variable " + m[1] + " is assigned a literal value at " + where + ". Read it from the Keychain at spawn instead of storing it in the script.",
			})
		}
	}
	if info.keychain {
		info.findings = append(info.findings, Finding{
			Rule: "KEYCHAIN_LAUNCHER", Severity: Info, Good: true,
			Title:  "Reads credentials from the macOS Keychain at spawn",
			Detail: "Launcher " + path + " calls `security find-*-password`, so no secret is stored in the MCP config. Good practice; the script itself was inspected rather than trusted as an unknown binary.",
		})
	}
	return info, true
}

// isLiteral reports whether a shell assignment's right-hand side is a fixed
// value rather than a substitution ($VAR, ${VAR}, $(cmd), `cmd`) or empty.
func isLiteral(rhs string) bool {
	v := strings.TrimSpace(rhs)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.Trim(v, `"'`)
	if v == "" {
		return false
	}
	return !strings.ContainsAny(v, "$`")
}
