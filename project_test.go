package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Project-scope (.mcp.json) comparison. Fixtures are synthetic: fake names,
// /fake/... paths, or files written to t.TempDir() at runtime.

func srvNode(script string) Server { return Server{Command: "node", Args: []string{script}} }

func collisionNamed(rep Report, name, context string) (Collision, bool) {
	for _, c := range rep.Collisions {
		if c.Name == name && c.Context == context {
			return c, true
		}
	}
	return Collision{}, false
}

func reportWithOrigin(rep Report, name, scope, project string) (ServerReport, bool) {
	for _, s := range reportsNamed(rep, name) {
		if hasOrigin(s, scope, project) {
			return s, true
		}
	}
	return ServerReport{}, false
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProjectFileReadsMcpJson(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"delta":{"command":"node","args":["/fake/opt/delta.js"]}}}`)
	pf, err := LoadProjectFile(repo)
	if err != nil {
		t.Fatalf("LoadProjectFile: %v", err)
	}
	if _, ok := pf.Servers["delta"]; !ok {
		t.Errorf("expected server delta, got %+v", pf.Servers)
	}
	if pf.Repo == "" || !filepath.IsAbs(pf.Repo) {
		t.Errorf("Repo should be an absolute path, got %q", pf.Repo)
	}
}

func TestLoadProjectFileMissingIsAnError(t *testing.T) {
	if _, err := LoadProjectFile(t.TempDir()); err == nil {
		t.Fatal("expected an error when the repo has no .mcp.json")
	}
}

func TestProjectScopeBeatsUserScope(t *testing.T) {
	cfg := &Config{
		MCPServers: map[string]Server{"dup": srvNode("/fake/opt/user.js")},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": srvNode("/fake/opt/project.js")}},
	}
	rep := Assess("synthetic", cfg)
	c, ok := collisionNamed(rep, "dup", "/fake/repo")
	if !ok {
		t.Fatalf("expected a collision for dup in /fake/repo, got %+v", rep.Collisions)
	}
	if c.Winner != ScopeProject {
		t.Errorf("winner = %q, want %q", c.Winner, ScopeProject)
	}
	if strings.Join(c.Scopes, ",") != "project,user" {
		t.Errorf("scopes = %v, want [project user] (precedence order)", c.Scopes)
	}
	proj, ok := reportWithOrigin(rep, "dup", ScopeProject, "/fake/repo")
	if !ok || !hasRule(proj.Findings, "SCOPE_SHADOW") {
		t.Errorf("project definition should carry SCOPE_SHADOW, got %+v", proj)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "dup") && strings.Contains(w, "/fake/repo") && strings.Contains(w, "project scope wins") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning saying project scope wins, got %v", rep.Warnings)
	}
}

func TestLocalScopeBeatsProjectScope(t *testing.T) {
	cfg := &Config{
		MCPServers: map[string]Server{"dup": srvNode("/fake/opt/user.js")},
		Projects:   map[string]Project{"/fake/repo": {MCPServers: map[string]Server{"dup": srvNode("/fake/opt/local.js")}}},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": srvNode("/fake/opt/project.js")}},
	}
	rep := Assess("synthetic", cfg)
	c, ok := collisionNamed(rep, "dup", "/fake/repo")
	if !ok {
		t.Fatalf("expected a collision, got %+v", rep.Collisions)
	}
	if c.Winner != ScopeLocal {
		t.Errorf("winner = %q, want %q", c.Winner, ScopeLocal)
	}
	if strings.Join(c.Scopes, ",") != "local,project,user" {
		t.Errorf("scopes = %v, want [local project user]", c.Scopes)
	}
	proj, ok := reportWithOrigin(rep, "dup", ScopeProject, "/fake/repo")
	if !ok || !hasRule(proj.Findings, "SCOPE_SHADOWED") {
		t.Errorf("project definition never runs there and should carry SCOPE_SHADOWED, got %+v", proj)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "dup") && strings.Contains(w, "local scope wins") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning saying local scope wins, got %v", rep.Warnings)
	}
}

func TestLocalScopeInAnotherProjectDoesNotCollideWithProjectFile(t *testing.T) {
	cfg := &Config{
		Projects: map[string]Project{"/fake/other": {MCPServers: map[string]Server{"dup": srvNode("/fake/opt/local.js")}}},
		Repo:     &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": srvNode("/fake/opt/project.js")}},
	}
	rep := Assess("synthetic", cfg)
	if len(rep.Collisions) != 0 || len(rep.Warnings) != 0 {
		t.Errorf("different projects never load together; got collisions %+v warnings %v", rep.Collisions, rep.Warnings)
	}
}

func TestProjectFileIdenticalToUserIsDuplicate(t *testing.T) {
	same := srvNode("/fake/opt/same.js")
	cfg := &Config{
		MCPServers: map[string]Server{"dup": same},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": same}},
	}
	rep := Assess("synthetic", cfg)
	if n := len(reportsNamed(rep, "dup")); n != 1 {
		t.Fatalf("identical definition should be reported once, got %d", n)
	}
	c, ok := collisionNamed(rep, "dup", "/fake/repo")
	if !ok || !c.Identical || c.Winner != ScopeProject {
		t.Errorf("want identical collision won by project, got %+v (ok=%v)", c, ok)
	}
	if !hasRule(reportsNamed(rep, "dup")[0].Findings, "SCOPE_DUPLICATE") {
		t.Errorf("expected SCOPE_DUPLICATE, got %+v", reportsNamed(rep, "dup")[0].Findings)
	}
}

func TestProjectFileWithoutOverlapHasNoCollision(t *testing.T) {
	cfg := &Config{
		MCPServers: map[string]Server{"alpha": srvNode("/fake/opt/a.js")},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"delta": srvNode("/fake/opt/d.js")}},
	}
	rep := Assess("synthetic", cfg)
	if len(rep.Collisions) != 0 || len(rep.Warnings) != 0 {
		t.Errorf("no shared names, got collisions %+v warnings %v", rep.Collisions, rep.Warnings)
	}
	if _, ok := reportWithOrigin(rep, "delta", ScopeProject, "/fake/repo"); !ok {
		t.Errorf("project-scope server delta should be assessed, got %+v", rep.Servers)
	}
}

func TestUserVsLocalCollisionIsRecorded(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	c, ok := collisionNamed(rep, "shared-diff", "/fake/home/proj-one")
	if !ok || c.Winner != ScopeLocal || strings.Join(c.Scopes, ",") != "local,user" || c.Identical {
		t.Errorf("want shared-diff won by local over user, got %+v (ok=%v)", c, ok)
	}
	if _, ok := collisionNamed(rep, "twin", "/fake/home/proj-one"); ok {
		t.Errorf("twin is not a collision")
	}
}

func TestTextOutputShowsProjectOrigin(t *testing.T) {
	cfg := &Config{
		MCPServers: map[string]Server{"dup": srvNode("/fake/opt/user.js")},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": srvNode("/fake/opt/project.js")}},
	}
	var buf bytes.Buffer
	Assess("synthetic", cfg).WriteText(&buf, Low)
	out := buf.String()
	for _, want := range []string{"project: /fake/repo", "project scope wins", "from: user"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestScannerComparesProjectRepo(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"dup":{"command":"node","args":["/fake/opt/project.js"]}}}`)
	conf := filepath.Join(dir, "claude.synthetic.json")
	writeFile(t, conf, `{"mcpServers":{"dup":{"command":"node","args":["/fake/opt/user.js"]}}}`)

	reports, err := NewScanner(WithProjectRepo(repo)).ScanFiles(context.Background(), []string{conf})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(reports) != 1 || len(reports[0].Collisions) != 1 || reports[0].Collisions[0].Winner != ScopeProject {
		t.Fatalf("expected one collision won by project, got %+v", reports)
	}
}

func TestScannerWithoutProjectRepoHasNoCollisions(t *testing.T) {
	reports, err := NewScanner().ScanFiles(context.Background(), []string{"examples/sample.mcp.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Collisions) != 0 {
		t.Errorf("plain config should have no collisions, got %+v", reports[0].Collisions)
	}
}

func TestScopeFindingsCarrySeverityLevelInJSON(t *testing.T) {
	cfg := &Config{
		MCPServers: map[string]Server{"dup": srvNode("/fake/opt/user.js")},
		Projects:   map[string]Project{"/fake/other": {MCPServers: map[string]Server{"dup": srvNode("/fake/opt/local.js")}}},
		Repo:       &ProjectFile{Repo: "/fake/repo", Servers: map[string]Server{"dup": srvNode("/fake/opt/project.js")}},
	}
	for _, s := range Assess("synthetic", cfg).Servers {
		for _, f := range s.Findings {
			if f.Level != f.Severity.String() {
				t.Errorf("%s: Level %q, want %q (JSON severity must not be empty)", f.Rule, f.Level, f.Severity.String())
			}
		}
	}
}
