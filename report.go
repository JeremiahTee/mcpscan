package main

import (
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// ServerReport is the assessment of a single MCP server.
type ServerReport struct {
	Name      string    `json:"name"`
	Transport string    `json:"transport"`
	Score     int       `json:"risk_score"`
	Band      string    `json:"risk_band"`
	Findings  []Finding `json:"findings"`
	Origins   []Origin  `json:"origins,omitempty"`
}

// Origin records where a server definition was declared: its scope and, for
// local scope, the project path it belongs to.
type Origin struct {
	Scope   string `json:"scope"`
	Project string `json:"project,omitempty"`
}

// Report is the full scan result across every server in a config.
type Report struct {
	Source       string         `json:"source"`
	OverallScore int            `json:"overall_score"`
	OverallBand  string         `json:"overall_band"`
	Servers      []ServerReport `json:"servers"`
	Warnings     []string       `json:"warnings,omitempty"`
	Collisions   []Collision    `json:"collisions,omitempty"`
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

// Assess builds a Report from a parsed config. Servers from every scope are
// assessed. A name defined identically in several scopes is reported once with
// all its origins; differing definitions are reported separately. A local-scope
// server that shares its name with a user-scope one silently shadows it in that
// project, so it carries a scope finding and the report gets a warning.
func Assess(source string, cfg *Config) Report {
	rep := Report{Source: source}

	// Group entries by name, then by identical definition, keeping first-seen order.
	type group struct {
		srv     Server
		origins []Origin
	}
	byName := map[string][]*group{}
	var names []string
	entries := cfg.Entries()
	rep.Collisions = collisions(entries)
	collisionAt := map[[2]string]Collision{}
	for _, c := range rep.Collisions {
		collisionAt[[2]string{c.Name, c.Context}] = c
	}
	for _, e := range entries {
		if _, ok := byName[e.Name]; !ok {
			names = append(names, e.Name)
		}
		o := Origin{Scope: e.Scope, Project: e.Project}
		merged := false
		for _, g := range byName[e.Name] {
			if reflect.DeepEqual(g.srv, e.Server) {
				g.origins = append(g.origins, o)
				merged = true
				break
			}
		}
		if !merged {
			byName[e.Name] = append(byName[e.Name], &group{srv: e.Server, origins: []Origin{o}})
		}
	}

	for _, name := range names {
		groups := byName[name]
		userDefined := false
		for _, g := range groups {
			for _, o := range g.origins {
				if o.Scope == ScopeUser {
					userDefined = true
				}
			}
		}
		for _, g := range groups {
			findings := Evaluate(name, g.srv)
			if userDefined {
				f, warns := scopeFindings(name, g.origins)
				findings = append(findings, f...)
				rep.Warnings = append(rep.Warnings, warns...)
			}
			for _, o := range g.origins {
				if o.Scope != ScopeProject {
					continue
				}
				c, ok := collisionAt[[2]string{name, filepath.Clean(o.Project)}]
				if !ok {
					continue
				}
				f, warn := projectFindings(g.origins, c)
				if f != nil {
					findings = append(findings, *f)
				}
				rep.Warnings = append(rep.Warnings, warn)
			}
			// Scope findings are added here, after Evaluate filled Level, so fill it
			// for every finding; otherwise JSON prints an empty severity.
			for i := range findings {
				findings[i].Level = findings[i].Severity.String()
			}
			sort.SliceStable(findings, func(i, j int) bool {
				return findings[i].Severity > findings[j].Severity
			})
			sc := score(findings)
			transport := "stdio"
			if g.srv.IsRemote() {
				transport = "remote"
			}
			rep.Servers = append(rep.Servers, ServerReport{
				Name:      name,
				Transport: transport,
				Score:     sc,
				Band:      band(sc),
				Findings:  findings,
				Origins:   g.origins,
			})
		}
	}
	// Deterministic order: riskiest first, then by name (stable, so user scope
	// precedes local for equal scores).
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

// scopeFindings explains how a definition interacts with a same-name user-scope
// server. It is called only when the name exists in user scope. A definition that
// also lives in user scope is the same server in both places (SCOPE_DUPLICATE,
// harmless). A local-only definition differs from the user one and wins in its
// project (SCOPE_SHADOW), which Claude Code does without any warning.
func scopeFindings(name string, origins []Origin) ([]Finding, []string) {
	inUser := false
	var projects []string
	for _, o := range origins {
		if o.Scope == ScopeUser {
			inUser = true
		} else if o.Scope == ScopeLocal {
			projects = append(projects, o.Project)
		}
	}
	if len(projects) == 0 {
		return nil, nil
	}
	list := strings.Join(projects, ", ")
	if inUser {
		return []Finding{{
				Rule: "SCOPE_DUPLICATE", Severity: Info,
				Title:  "Same server declared in user and local scope",
				Detail: "Defined identically in user scope and for project(s) " + list + ". Harmless today, but an edit to one copy will silently shadow the other.",
			}}, []string{
				"name collision: " + name + " is declared in user scope and again (identically) in local scope for " + list + "; the local copy wins there",
			}
	}
	return []Finding{{
			Rule: "SCOPE_SHADOW", Severity: Low,
			Title:  "Silently shadows a user-scope server of the same name",
			Detail: "In project(s) " + list + " this local-scope definition replaces the user-scope " + name + " (precedence local > project > user) with no warning from the client. Confirm which one you expect to run there.",
		}}, []string{
			"name collision: " + name + " differs between user scope and local scope for " + list + "; the local definition silently wins there",
		}
}

// WriteText renders a human-readable report. minSeverity hides findings below the
// given level so an operator can focus on what matters. Good-practice findings and
// scope warnings are always shown. Origins are printed only when the config has
// local-scope servers, so a plain single-scope config renders exactly as before.
func (r Report) WriteText(w io.Writer, minSeverity Severity) {
	fmt.Fprintf(w, "mcpscan — %s\n", r.Source)
	fmt.Fprintf(w, "overall risk: %d/100 (%s) across %d server(s)\n", r.OverallScore, r.OverallBand, len(r.Servers))
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	fmt.Fprintln(w)
	showOrigins := r.hasLocalScope()
	for _, s := range r.Servers {
		fmt.Fprintf(w, "%s  [%s]  %d/100 %s\n", s.Name, s.Transport, s.Score, s.Band)
		if showOrigins {
			fmt.Fprintf(w, "  from: %s\n", formatOrigins(s.Origins))
		}
		shown := 0
		for _, f := range s.Findings {
			if f.Good {
				fmt.Fprintf(w, "  + %-6s %-22s %s\n", "GOOD", f.Rule, f.Title)
				fmt.Fprintf(w, "           %s\n", f.Detail)
				shown++
				continue
			}
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

// hasLocalScope reports whether any server comes from a scope other than user
// (local, or a .mcp.json project file), which is when origins are worth printing.
func (r Report) hasLocalScope() bool {
	for _, s := range r.Servers {
		for _, o := range s.Origins {
			if o.Scope != ScopeUser {
				return true
			}
		}
	}
	return false
}

func formatOrigins(origins []Origin) string {
	parts := make([]string, 0, len(origins))
	for _, o := range origins {
		if o.Project != "" {
			parts = append(parts, o.Scope+": "+o.Project)
		} else {
			parts = append(parts, o.Scope)
		}
	}
	return strings.Join(parts, "; ")
}
