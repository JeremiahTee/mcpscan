package main

import (
	"bytes"
	"strings"
	"testing"
)

// All fixtures in testdata/ are synthetic: fake paths, fake server names, no real values.

func mustLoad(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%q): %v", path, err)
	}
	return cfg
}

// reportsNamed returns every server report with the given name.
func reportsNamed(rep Report, name string) []ServerReport {
	var out []ServerReport
	for _, s := range rep.Servers {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func hasOrigin(s ServerReport, scope, project string) bool {
	for _, o := range s.Origins {
		if o.Scope == scope && o.Project == project {
			return true
		}
	}
	return false
}

func TestLoadConfigReadsProjectScopedServers(t *testing.T) {
	cfg := mustLoad(t, "testdata/scopes.synthetic.json")
	got := map[string]bool{}
	for _, e := range cfg.Entries() {
		got[e.Scope+"|"+e.Project+"|"+e.Name] = true
	}
	for _, want := range []string{
		ScopeUser + "||alpha",
		ScopeLocal + "|/fake/home/proj-one|beta",
		ScopeLocal + "|/fake/home/proj-two|twin",
	} {
		if !got[want] {
			t.Errorf("missing entry %q in %v", want, got)
		}
	}
}

func TestLoadConfigAcceptsProjectsOnly(t *testing.T) {
	cfg := mustLoad(t, "testdata/projects-only.synthetic.json")
	if n := len(cfg.Entries()); n != 1 {
		t.Fatalf("want 1 entry, got %d", n)
	}
}

func TestAssessReportsProjectPath(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	beta := reportsNamed(rep, "beta")
	if len(beta) != 1 || !hasOrigin(beta[0], ScopeLocal, "/fake/home/proj-one") {
		t.Fatalf("beta should come from local scope /fake/home/proj-one, got %+v", beta)
	}
	alpha := reportsNamed(rep, "alpha")
	if len(alpha) != 1 || !hasOrigin(alpha[0], ScopeUser, "") {
		t.Fatalf("alpha should come from user scope, got %+v", alpha)
	}
}

func TestAssessDedupsIdenticalDefinitionAcrossScopes(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	same := reportsNamed(rep, "shared-same")
	if len(same) != 1 {
		t.Fatalf("identical definition in two scopes should be reported once, got %d", len(same))
	}
	if !hasOrigin(same[0], ScopeUser, "") || !hasOrigin(same[0], ScopeLocal, "/fake/home/proj-one") {
		t.Errorf("merged report should list both origins, got %+v", same[0].Origins)
	}
	if !hasRule(same[0].Findings, "SCOPE_DUPLICATE") {
		t.Errorf("expected SCOPE_DUPLICATE, got %+v", same[0].Findings)
	}
}

func TestAssessWarnsOnShadowingCollision(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	diff := reportsNamed(rep, "shared-diff")
	if len(diff) != 2 {
		t.Fatalf("different definitions should stay separate, got %d", len(diff))
	}
	var local ServerReport
	for _, s := range diff {
		if hasOrigin(s, ScopeLocal, "/fake/home/proj-one") {
			local = s
		}
	}
	if !hasRule(local.Findings, "SCOPE_SHADOW") {
		t.Errorf("local copy should carry SCOPE_SHADOW, got %+v", local.Findings)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "shared-diff") && strings.Contains(w, "/fake/home/proj-one") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a collision warning naming shared-diff and the project, got %v", rep.Warnings)
	}
}

func TestSameNameInTwoProjectsIsNotACollision(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	for _, w := range rep.Warnings {
		if strings.Contains(w, "twin") {
			t.Errorf("twin lives in two different projects, which never load together: %q", w)
		}
	}
	for _, s := range reportsNamed(rep, "twin") {
		if hasRule(s.Findings, "SCOPE_SHADOW") || hasRule(s.Findings, "SCOPE_DUPLICATE") {
			t.Errorf("twin should carry no scope finding, got %+v", s.Findings)
		}
	}
}

func TestTextOutputShowsOriginAndWarning(t *testing.T) {
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	var buf bytes.Buffer
	rep.WriteText(&buf, Low)
	out := buf.String()
	for _, want := range []string{"local: /fake/home/proj-one", "warning:", "shared-diff"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestTopLevelOnlyOutputUnchanged(t *testing.T) {
	// A plain config (no projects) should not grow scope labels.
	rep := Assess("sample", mustLoad(t, "examples/sample.mcp.json"))
	var buf bytes.Buffer
	rep.WriteText(&buf, Low)
	if strings.Contains(buf.String(), "from:") || len(rep.Warnings) != 0 {
		t.Errorf("top-level-only config should render as before:\n%s", buf.String())
	}
}
