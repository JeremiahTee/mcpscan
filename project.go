package main

import "errors"

// ScopeProject is a server declared in a repository's .mcp.json.
const ScopeProject = "project"

// ProjectFile is a repository's .mcp.json.
type ProjectFile struct {
	Repo    string
	Servers map[string]Server
}

// Collision records one name declared in more than one scope that load together.
type Collision struct {
	Name      string   `json:"name"`
	Context   string   `json:"context"`
	Scopes    []string `json:"scopes"`
	Winner    string   `json:"winner"`
	Identical bool     `json:"identical"`
}

// LoadProjectFile reads <repo>/.mcp.json. (stub)
func LoadProjectFile(repo string) (*ProjectFile, error) { return nil, errors.New("not implemented") }

// WithProjectRepo compares each scanned config against <repo>/.mcp.json. (stub)
func WithProjectRepo(repo string) Option { return func(*Scanner) {} }
