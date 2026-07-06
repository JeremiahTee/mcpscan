package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config mirrors the shape of a Claude Desktop / Claude Code MCP configuration
// file. Only the fields relevant to a static risk assessment are modeled; unknown
// fields are ignored so the scanner tolerates real-world configs it did not author.
type Config struct {
	MCPServers map[string]Server `json:"mcpServers"`
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
	if len(cfg.MCPServers) == 0 {
		return nil, fmt.Errorf("no servers found under \"mcpServers\" in %q", path)
	}
	return &cfg, nil
}
