package main

import (
	"fmt"
	"io"
	"sort"
)

// ServerReport is the assessment of a single MCP server.
type ServerReport struct {
	Name      string    `json:"name"`
	Transport string    `json:"transport"`
	Score     int       `json:"risk_score"`
	Band      string    `json:"risk_band"`
	Findings  []Finding `json:"findings"`
}

// Report is the full scan result across every server in a config.
type Report struct {
	Source       string         `json:"source"`
	OverallScore int            `json:"overall_score"`
	OverallBand  string         `json:"overall_band"`
	Servers      []ServerReport `json:"servers"`
}

// score converts findings into a 0-100 risk score. Weights are summed and capped;
// the mapping is intentionally simple so the number is explainable from the findings.
func score(findings []Finding) int {
	total := 0
	for _, f := range findings {
		total += f.Severity.weight()
	}
	if total > 100 {
		total = 100
	}
	return total
}

func band(score int) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "clean"
	}
}

// Assess builds a Report from a parsed config.
func Assess(source string, cfg *Config) Report {
	rep := Report{Source: source}
	for name, srv := range cfg.MCPServers {
		findings := Evaluate(name, srv)
		sort.SliceStable(findings, func(i, j int) bool {
			return findings[i].Severity > findings[j].Severity
		})
		sc := score(findings)
		transport := "stdio"
		if srv.IsRemote() {
			transport = "remote"
		}
		rep.Servers = append(rep.Servers, ServerReport{
			Name:      name,
			Transport: transport,
			Score:     sc,
			Band:      band(sc),
			Findings:  findings,
		})
	}
	// Deterministic order: riskiest first, then by name.
	sort.SliceStable(rep.Servers, func(i, j int) bool {
		if rep.Servers[i].Score != rep.Servers[j].Score {
			return rep.Servers[i].Score > rep.Servers[j].Score
		}
		return rep.Servers[i].Name < rep.Servers[j].Name
	})
	// Overall score is the worst single server: a config is only as safe as its
	// most-exposed connection.
	for _, s := range rep.Servers {
		if s.Score > rep.OverallScore {
			rep.OverallScore = s.Score
		}
	}
	rep.OverallBand = band(rep.OverallScore)
	return rep
}

// WriteText renders a human-readable report. minSeverity hides findings below the
// given level so an operator can focus on what matters.
func (r Report) WriteText(w io.Writer, minSeverity Severity) {
	fmt.Fprintf(w, "mcpscan — %s\n", r.Source)
	fmt.Fprintf(w, "overall risk: %d/100 (%s) across %d server(s)\n\n", r.OverallScore, r.OverallBand, len(r.Servers))
	for _, s := range r.Servers {
		fmt.Fprintf(w, "%s  [%s]  %d/100 %s\n", s.Name, s.Transport, s.Score, s.Band)
		shown := 0
		for _, f := range s.Findings {
			if f.Severity < minSeverity {
				continue
			}
			fmt.Fprintf(w, "  - %-6s %-22s %s\n", f.Severity, f.Rule, f.Title)
			fmt.Fprintf(w, "           %s\n", f.Detail)
			shown++
		}
		if shown == 0 {
			fmt.Fprintf(w, "  (no findings at or above %s)\n", minSeverity)
		}
		fmt.Fprintln(w)
	}
}
