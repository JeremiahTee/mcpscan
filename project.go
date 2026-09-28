package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// ScopeProject is a server declared in a repository's .mcp.json. Claude Code
// resolves a name by precedence local > project > user.
const ScopeProject = "project"

// scopeRank orders scopes by precedence; a higher rank wins.
var scopeRank = map[string]int{ScopeLocal: 3, ScopeProject: 2, ScopeUser: 1}

// ProjectFile is a repository's .mcp.json, compared against ~/.claude.json.
type ProjectFile struct {
	Repo    string // absolute, cleaned repository path
	Servers map[string]Server
}

// Collision records one server name declared in more than one scope that load
// together in the same project. Scopes are listed highest precedence first;
// Winner is the scope whose definition actually runs there.
type Collision struct {
	Name      string   `json:"name"`
	Context   string   `json:"context"`
	Scopes    []string `json:"scopes"`
	Winner    string   `json:"winner"`
	Identical bool     `json:"identical"`
}

// LoadProjectFile reads <repo>/.mcp.json. The repo path is made absolute and,
// where possible, symlink-resolved so it can match the project keys in
// ~/.claude.json. A missing or malformed file is an error.
func LoadProjectFile(repo string) (*ProjectFile, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("project repo %q: %w", repo, err)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	path := filepath.Join(abs, ".mcp.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read project file: %w", err)
	}
	var f struct {
		MCPServers map[string]Server `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse project file %q: %w", path, err)
	}
	return &ProjectFile{Repo: filepath.Clean(abs), Servers: f.MCPServers}, nil
}

// WithProjectRepo makes the Scanner compare each config against the servers in
// <repo>/.mcp.json (project scope).
func WithProjectRepo(repo string) Option {
	return func(s *Scanner) { s.projectRepo = repo }
}

// collisions finds every name that is declared in more than one scope loading
// together. User scope loads everywhere; local scope loads in its project;
// project scope (.mcp.json) loads in its repo. Two different projects never
// load together.
func collisions(entries []Entry) []Collision {
	type key struct{ name, ctx string }
	defs := map[key]map[string]Server{} // scope -> definition, per (name, context)
	user := map[string]Server{}
	for _, e := range entries {
		if e.Scope == ScopeUser {
			user[e.Name] = e.Server
		}
	}
	for _, e := range entries {
		if e.Scope == ScopeUser {
			continue
		}
		k := key{e.Name, filepath.Clean(e.Project)}
		if defs[k] == nil {
			defs[k] = map[string]Server{}
		}
		defs[k][e.Scope] = e.Server
	}
	var out []Collision
	for k, m := range defs {
		if u, ok := user[k.name]; ok {
			m[ScopeUser] = u
		}
		if len(m) < 2 {
			continue
		}
		c := Collision{Name: k.name, Context: k.ctx, Identical: true}
		for sc := range m {
			c.Scopes = append(c.Scopes, sc)
		}
		sort.Slice(c.Scopes, func(i, j int) bool { return scopeRank[c.Scopes[i]] > scopeRank[c.Scopes[j]] })
		c.Winner = c.Scopes[0]
		for _, sc := range c.Scopes[1:] {
			if !reflect.DeepEqual(m[sc], m[c.Winner]) {
				c.Identical = false
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Context < out[j].Context
	})
	return out
}

// projectFindings explains how a project-scope (.mcp.json) definition fares in
// its collision: it replaces a different user-scope server (SCOPE_SHADOW), it is
// the same server as the one it collides with (SCOPE_DUPLICATE), or a local-scope
// server of the same name wins and this definition never runs (SCOPE_SHADOWED).
func projectFindings(g []Origin, c Collision) (*Finding, string) {
	has := func(scope string) bool {
		for _, o := range g {
			if o.Scope == scope {
				return true
			}
		}
		return false
	}
	others := joinScopes(c.Scopes)
	switch {
	case c.Winner == ScopeLocal && !has(ScopeLocal):
		return &Finding{
			Rule: "SCOPE_SHADOWED", Severity: Info,
			Title:  "Hidden by a local-scope server of the same name",
			Detail: "In " + c.Context + " the .mcp.json definition of " + c.Name + " never runs: a local-scope server of the same name wins (precedence local > project > user) and the client does not say so.",
		}, "name collision in " + c.Context + ": " + c.Name + " is declared in " + others + " scope; local scope wins (local > project > user), so the .mcp.json definition never runs there"
	case c.Winner == ScopeProject && c.Identical:
		return &Finding{
			Rule: "SCOPE_DUPLICATE", Severity: Info,
			Title:  "Same server declared in project and user scope",
			Detail: "Defined identically in " + c.Context + "/.mcp.json and in user scope. Harmless today, but an edit to one copy will silently shadow the other.",
		}, "name collision in " + c.Context + ": " + c.Name + " is declared identically in " + others + " scope; project scope wins (local > project > user)"
	case c.Winner == ScopeProject:
		return &Finding{
			Rule: "SCOPE_SHADOW", Severity: Low,
			Title:  "Silently shadows a user-scope server of the same name",
			Detail: "In " + c.Context + " this .mcp.json definition replaces the user-scope " + c.Name + " (precedence local > project > user) with no warning from the client. Confirm which one you expect to run there.",
		}, "name collision in " + c.Context + ": " + c.Name + " differs between " + others + " scope; project scope wins (local > project > user)"
	}
	// Local wins and this definition is the local one too: nothing is hidden
	// that differs from what runs, but the name is still declared twice.
	return nil, "name collision in " + c.Context + ": " + c.Name + " is declared in " + others + " scope; local scope wins (local > project > user) and the .mcp.json copy matches it"
}

func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		switch {
		case i == 0:
		case i == len(scopes)-1:
			out += " and "
		default:
			out += ", "
		}
		out += s
	}
	return out
}
