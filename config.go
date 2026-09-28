package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Config mirrors the shape of a Claude Desktop / Claude Code MCP configuration
// file. Only the fields relevant to a static risk assessment are modeled; unknown
// fields are ignored so the scanner tolerates real-world configs it did not author.
//
// Claude Code's ~/.claude.json holds servers in two places: the top-level
// "mcpServers" map (user scope, loaded in every project) and
// "projects.<path>.mcpServers" (local scope, loaded only in that project).
type Config struct {
	MCPServers map[string]Server  `json:"mcpServers"`
	Projects   map[string]Project `json:"projects"`
	// Repo is a repository's .mcp.json (project scope), attached by the
	// scanner when -project is given; it is not part of the JSON file.
	Repo *ProjectFile `json:"-"`
}

// Project is one entry under "projects"; only its servers are modeled.
type Project struct {
	MCPServers map[string]Server `json:"mcpServers"`
}

// Scopes a server can be declared in. Claude Code resolves a name by
// precedence local > project (.mcp.json) > user, and a lower-precedence
// server with the same name is hidden silently, with no warning.
const (
	ScopeUser  = "user"
	ScopeLocal = "local"
)

// Entry is one server definition together with where it was declared.
// Project is empty for user-scope entries.
type Entry struct {
	Name    string
	Server  Server
	Scope   string
	Project string
}

// Entries flattens every server in the config into a deterministic list:
// user scope first, then the attached .mcp.json (project scope, if any), then
// each local-scope project by path, names sorted within each.
func (c *Config) Entries() []Entry {
	var out []Entry
	for _, name := range sortedKeys(c.MCPServers) {
		out = append(out, Entry{Name: name, Server: c.MCPServers[name], Scope: ScopeUser})
	}
	if c.Repo != nil {
		for _, name := range sortedKeys(c.Repo.Servers) {
			out = append(out, Entry{Name: name, Server: c.Repo.Servers[name], Scope: ScopeProject, Project: c.Repo.Repo})
		}
	}
	paths := make([]string, 0, len(c.Projects))
	for p := range c.Projects {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		servers := c.Projects[p].MCPServers
		for _, name := range sortedKeys(servers) {
			out = append(out, Entry{Name: name, Server: servers[name], Scope: ScopeLocal, Project: p})
		}
	}
	return out
}

func sortedKeys(m map[string]Server) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Server is one entry under "mcpServers". A stdio server sets Command/Args/Env;
// a remote server sets URL (SSE or streamable HTTP transport).
type Server struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

// IsRemote reports whether the server is reached over the network rather than
// launched as a local subprocess.
func (s Server) IsRemote() bool {
	return s.URL != ""
}

// LoadConfig reads and parses an MCP configuration file from disk.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if len(cfg.Entries()) == 0 {
		return nil, fmt.Errorf("no servers found under \"mcpServers\" or \"projects.*.mcpServers\" in %q", path)
	}
	return &cfg, nil
}
