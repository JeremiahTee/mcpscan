package main

import "testing"

// hasRule reports whether findings contain a given rule id.
func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestSecretInEnv(t *testing.T) {
	f := Evaluate("github", Server{
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-github"},
		Env:     map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "x"},
	})
	if !hasRule(f, "SECRET_IN_ENV") {
		t.Errorf("expected SECRET_IN_ENV, got %+v", f)
	}
}

func TestBroadFilesystem(t *testing.T) {
	f := Evaluate("filesystem", Server{
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem", "/"},
	})
	if !hasRule(f, "BROAD_FS_ACCESS") {
		t.Errorf("expected BROAD_FS_ACCESS for root mount, got %+v", f)
	}
}

func TestNarrowFilesystemIsClean(t *testing.T) {
	f := Evaluate("filesystem", Server{
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/j/projects/app"},
	})
	if hasRule(f, "BROAD_FS_ACCESS") {
		t.Errorf("did not expect BROAD_FS_ACCESS for a scoped dir, got %+v", f)
	}
}

func TestInsecureRemote(t *testing.T) {
	f := Evaluate("search", Server{URL: "http://internal.example.com/sse"})
	if !hasRule(f, "INSECURE_TRANSPORT") {
		t.Errorf("expected INSECURE_TRANSPORT for http url, got %+v", f)
	}
	if !hasRule(f, "REMOTE_TRANSPORT") {
		t.Errorf("expected REMOTE_TRANSPORT for remote server, got %+v", f)
	}
}

func TestArbitraryBinary(t *testing.T) {
	f := Evaluate("internal", Server{Command: "/opt/company/bin/mcp-internal"})
	if !hasRule(f, "ARBITRARY_BINARY") {
		t.Errorf("expected ARBITRARY_BINARY, got %+v", f)
	}
}

func TestDockerSensitiveMount(t *testing.T) {
	f := Evaluate("pg", Server{
		Command: "docker",
		Args:    []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "mcp/pg"},
	})
	if !hasRule(f, "DOCKER_SENSITIVE_MOUNT") {
		t.Errorf("expected DOCKER_SENSITIVE_MOUNT, got %+v", f)
	}
}

func TestScoreAndBand(t *testing.T) {
	// One HIGH (40) + one MEDIUM (20) = 60 -> critical.
	findings := []Finding{{Severity: High}, {Severity: Medium}}
	if got := score(findings); got != 60 {
		t.Errorf("score = %d, want 60", got)
	}
	if got := band(60); got != "critical" {
		t.Errorf("band(60) = %q, want critical", got)
	}
	if band(0) != "clean" {
		t.Errorf("band(0) should be clean")
	}
}
