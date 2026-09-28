package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Secrets inside a scanned config must never reach the report. Every value here
// is fake; the "secret" strings are assembled at runtime so no credential-shaped
// literal is committed.

var (
	fakeQuerySecret    = "fake" + "-query-" + strings.Repeat("0", 24)
	fakeUserinfoSecret = "fake" + "-userinfo-" + strings.Repeat("1", 24)
	fakeSpecSecret     = "fake" + "-spec-" + strings.Repeat("2", 24)
)

// renderBoth returns the text and JSON renderings of a report for cfg.
func renderBoth(t *testing.T, cfg *Config) (string, string) {
	t.Helper()
	rep := Assess("fake-config.json", cfg)
	var buf bytes.Buffer
	rep.WriteText(&buf, Info)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return buf.String(), string(raw)
}

func assertRedacted(t *testing.T, out, kind string, secrets, keep []string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%s output leaks a secret from the config:\n%s", kind, out)
		}
	}
	for _, k := range keep {
		if !strings.Contains(out, k) {
			t.Errorf("%s output should still name %q:\n%s", kind, k, out)
		}
	}
}

func TestRemoteURLSecretsNeverPrinted(t *testing.T) {
	cfg := &Config{MCPServers: map[string]Server{
		"fake-query": {URL: "https://query.example.invalid/v1/sse?api_key=" + fakeQuerySecret + "&x=1#frag-" + fakeQuerySecret},
		"fake-userinfo": {URL: "https://fakeuser:" + fakeUserinfoSecret + "@userinfo.example.invalid:8443/mcp"},
	}}
	text, js := renderBoth(t, cfg)
	secrets := []string{fakeQuerySecret, fakeUserinfoSecret, "fakeuser", "api_key"}
	keep := []string{"https://query.example.invalid/v1/sse?<redacted>", "https://userinfo.example.invalid:8443/mcp"}
	assertRedacted(t, text, "text", secrets, keep)
	assertRedacted(t, js, "JSON", secrets, keep)
}

func TestUnpinnedSpecURLSecretsNeverPrinted(t *testing.T) {
	cfg := &Config{MCPServers: map[string]Server{
		"fake-spec": {Command: "uvx", Args: []string{"--from", "git+https://fakeuser:" + fakeSpecSecret + "@git.example.invalid/org/repo.git", "fake-tool"}},
	}}
	text, js := renderBoth(t, cfg)
	secrets := []string{fakeSpecSecret, "fakeuser"}
	keep := []string{"UNPINNED_PACKAGE", "git+https://git.example.invalid/org/repo.git"}
	assertRedacted(t, text, "text", secrets, keep)
	assertRedacted(t, js, "JSON", secrets, keep)
}

func TestSanitizeURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://h.example.invalid/sse", "https://h.example.invalid/sse"},
		{"https://h.example.invalid:8443/a/b", "https://h.example.invalid:8443/a/b"},
		{"https://h.example.invalid/sse?k=" + fakeQuerySecret, "https://h.example.invalid/sse?<redacted>"},
		{"https://h.example.invalid/sse#" + fakeQuerySecret, "https://h.example.invalid/sse#<redacted>"},
		{"https://u:" + fakeUserinfoSecret + "@h.example.invalid/p", "https://h.example.invalid/p"},
		{"https://" + fakeUserinfoSecret + "@h.example.invalid", "https://h.example.invalid"},
		// Ambiguous: an unescaped # or / in a password moves the "@" out of the
		// authority, so the parser would read part of the secret as the host.
		{"https://u:12#" + fakeUserinfoSecret + "@h.example.invalid/p", unparseableURL},
		{"https://u:12/" + fakeUserinfoSecret + "@h.example.invalid", unparseableURL},
		{"https://h.example.invalid?k=" + fakeQuerySecret + "@x", unparseableURL},
		{"not a url " + fakeQuerySecret, unparseableURL},
		{"://" + fakeQuerySecret, unparseableURL},
		{"mailto:" + fakeQuerySecret, unparseableURL},
	} {
		got := sanitizeURL(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeURL(<case %q>) = %q, want %q", tc.want, got, tc.want)
		}
		if strings.Contains(got, fakeQuerySecret) || strings.Contains(got, fakeUserinfoSecret) {
			t.Errorf("sanitizeURL leaked a secret: %q", got)
		}
	}
}

// A commented-out Keychain call is not a Keychain read: it must not earn the
// KEYCHAIN_LAUNCHER good-practice signal or suppress ARBITRARY_BINARY.
func TestCommentedKeychainCallIsNotGoodPractice(t *testing.T) {
	body := "#!/bin/bash\n# security find-generic-password -s fake-mcp-service -w\nexec /fake/opt/bin/thing\n"
	f := Evaluate("fake-svc", Server{Command: writeScript(t, body)})
	if hasRule(f, "KEYCHAIN_LAUNCHER") {
		t.Errorf("a commented-out keychain call must not earn KEYCHAIN_LAUNCHER, got %+v", f)
	}
	if !hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("a script whose only keychain call is commented out stays ARBITRARY_BINARY, got %+v", f)
	}
}
