package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Launcher scripts are written to a temp dir at test time. Every value is fake;
// token-shaped strings are assembled at runtime so no literal lands in the repo.

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "launch.sh")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func findRule(findings []Finding, rule string) (Finding, bool) {
	for _, f := range findings {
		if f.Rule == rule {
			return f, true
		}
	}
	return Finding{}, false
}

const keychainLauncher = `#!/bin/bash
# Synthetic launcher: reads a fake Keychain item at spawn.
export FAKE_CLIENT_SECRET="$(security find-generic-password -s fake-mcp-service -w)"
exec node /fake/opt/server/index.js "$@"
`

func TestKeychainLauncherIsGoodPractice(t *testing.T) {
	f := Evaluate("fake-svc", Server{Command: writeScript(t, keychainLauncher)})
	if hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("keychain launcher should not be ARBITRARY_BINARY, got %+v", f)
	}
	kc, ok := findRule(f, "KEYCHAIN_LAUNCHER")
	if !ok || !kc.Good {
		t.Errorf("expected a Good KEYCHAIN_LAUNCHER finding, got %+v", f)
	}
	if hasRule(f, "SECRET_IN_LAUNCHER") {
		t.Errorf("a $(security ...) substitution is not a literal secret, got %+v", f)
	}
	if score(f) != 0 {
		t.Errorf("keychain launcher should add no risk, score = %d", score(f))
	}
}

func TestKeychainLauncherWithLiteralSecretStillFlagged(t *testing.T) {
	const fakeValue = "fake-literal-value-not-a-real-token-0000"
	body := keychainLauncher + "export FAKE_API_TOKEN=\"" + fakeValue + "\"\n"
	f := Evaluate("fake-svc", Server{Command: writeScript(t, body)})
	sec, ok := findRule(f, "SECRET_IN_LAUNCHER")
	if !ok || sec.Severity != High {
		t.Fatalf("expected HIGH SECRET_IN_LAUNCHER, got %+v", f)
	}
	if !strings.Contains(sec.Detail, "FAKE_API_TOKEN") {
		t.Errorf("detail should name the variable, got %q", sec.Detail)
	}
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), fakeValue) {
		t.Errorf("secret value leaked into findings: %s", raw)
	}
}

func TestLauncherTokenShapedLiteralFlagged(t *testing.T) {
	fakePAT := "gh" + "p_" + strings.Repeat("0", 36)
	body := "#!/bin/sh\nexec fake-server --auth " + fakePAT + "\n"
	f := Evaluate("fake-svc", Server{Command: writeScript(t, body)})
	if !hasRule(f, "SECRET_IN_LAUNCHER") {
		t.Errorf("expected SECRET_IN_LAUNCHER for a token-shaped literal, got %+v", f)
	}
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), fakePAT) {
		t.Errorf("token leaked into findings: %s", raw)
	}
}

func TestPlainScriptStillUnrecognised(t *testing.T) {
	f := Evaluate("fake-svc", Server{Command: writeScript(t, "#!/bin/sh\nexec /fake/opt/bin/thing\n")})
	if !hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("a script without the keychain pattern stays ARBITRARY_BINARY, got %+v", f)
	}
	if hasRule(f, "KEYCHAIN_LAUNCHER") {
		t.Errorf("no keychain call, no KEYCHAIN_LAUNCHER, got %+v", f)
	}
}

func TestShellInterpreterInspectsScriptArg(t *testing.T) {
	f := Evaluate("fake-svc", Server{Command: "/bin/bash", Args: []string{writeScript(t, keychainLauncher)}})
	if hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("bash <keychain launcher> should not be ARBITRARY_BINARY, got %+v", f)
	}
	if !hasRule(f, "KEYCHAIN_LAUNCHER") {
		t.Errorf("expected KEYCHAIN_LAUNCHER via bash arg, got %+v", f)
	}
}

func TestMissingLauncherFallsBackToUnrecognised(t *testing.T) {
	f := Evaluate("fake-svc", Server{Command: "/fake/does/not/exist/launch.sh"})
	if !hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("unreadable launcher should stay ARBITRARY_BINARY, got %+v", f)
	}
}
