package main

import "testing"

// Version-pinning cases for UNPINNED_PACKAGE. Package names are synthetic.

func TestUnpinnedPackage(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		args     []string
		unpinned bool
	}{
		// npx
		{"npx exact version", "npx", []string{"-y", "fake-mcp@1.2.3"}, false},
		{"npx scoped exact version", "npx", []string{"-y", "@fake-scope/fake-mcp@1.2.3"}, false},
		{"npx no version", "npx", []string{"-y", "fake-mcp"}, true},
		{"npx scoped no version", "npx", []string{"-y", "@fake-scope/fake-mcp"}, true},
		{"npx @latest", "npx", []string{"-y", "fake-mcp@latest"}, true},
		{"npx scoped @latest", "npx", []string{"@fake-scope/fake-mcp@latest"}, true},
		{"npx dist-tag", "npx", []string{"fake-mcp@next"}, true},
		{"npx caret range", "npx", []string{"fake-mcp@^1.2.0"}, true},
		{"npx prerelease exact", "npx", []string{"fake-mcp@1.2.3-beta.1"}, false},
		// uvx, pip-style specifiers
		{"uvx == pin", "uvx", []string{"fake-mcp==1.2"}, false},
		{"uvx === pin", "uvx", []string{"fake-mcp===1.2.3"}, false},
		{"uvx extras + == pin", "uvx", []string{"fake-mcp[cli]==1.2"}, false},
		{"uvx >= is a range", "uvx", []string{"fake-mcp>=1.2"}, true},
		{"uvx ~= is a range", "uvx", []string{"fake-mcp~=1.2"}, true},
		{"uvx bare name", "uvx", []string{"fake-mcp"}, true},
		{"uvx @version", "uvx", []string{"fake-mcp@1.2.0"}, false},
		{"uvx @latest", "uvx", []string{"fake-mcp@latest"}, true},
		{"uvx --from pinned", "uvx", []string{"--from", "fake-mcp==1.2", "fake-cmd"}, false},
		{"uvx --from= pinned", "uvx", []string{"--from=fake-mcp==1.2", "fake-cmd"}, false},
		{"uvx --from unpinned", "uvx", []string{"--from", "fake-mcp", "fake-cmd"}, true},
		{"uvx --from range", "uvx", []string{"--from", "fake-mcp>=1.2", "fake-cmd"}, true},
		{"uvx --python value skipped", "uvx", []string{"--python", "3.12", "fake-mcp==1.2"}, false},
		{"uv tool run pinned", "uv", []string{"tool", "run", "fake-mcp==1.2"}, false},
		{"uv tool run unpinned", "uv", []string{"tool", "run", "fake-mcp"}, true},
		// other launchers are not assessed for pinning
		{"node script", "node", []string{"/fake/opt/index.js"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Evaluate("fake", Server{Command: c.command, Args: c.args})
			if got := hasRule(f, "UNPINNED_PACKAGE"); got != c.unpinned {
				t.Errorf("%s %v: UNPINNED_PACKAGE=%v, want %v (findings %+v)", c.command, c.args, got, c.unpinned, f)
			}
		})
	}
}

func TestSyntheticBetaUvxPinIsNotFlagged(t *testing.T) {
	// The fixture's beta server is `uvx fake-beta-mcp==0.1.0`: a real pin.
	rep := Assess("synthetic", mustLoad(t, "testdata/scopes.synthetic.json"))
	for _, s := range reportsNamed(rep, "beta") {
		if hasRule(s.Findings, "UNPINNED_PACKAGE") {
			t.Errorf("beta is pinned with ==, got %+v", s.Findings)
		}
	}
}
