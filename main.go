// Command mcpscan statically audits Model Context Protocol (MCP) server
// configurations and produces an explainable, scored risk report.
//
// It reads Claude Desktop / Claude Code style configs (a JSON object with an
// "mcpServers" map) and, for each connected server, flags where the agent's tool
// surface is over-privileged or exposed: credentials handed to subprocesses,
// remote code fetched at launch, broad filesystem roots, privileged containers,
// and cleartext transports. Every finding carries the reason it fired, so the
// score is auditable rather than a black box.
//
// Multiple config files (or globs) can be scanned at once, concurrently. Useful
// for auditing an entire team or fleet of developer machines in one pass.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var (
		asJSON      bool
		minLevel    string
		failOn      string
		concurrency int
		listRules   bool
		projectRepo string
	)
	flag.BoolVar(&asJSON, "json", false, "emit the report as JSON")
	flag.StringVar(&minLevel, "min-severity", "low", "hide findings below this level (info|low|medium|high)")
	flag.StringVar(&failOn, "fail-on", "", "exit non-zero if any config reaches this band (low|medium|high|critical); for CI gating")
	flag.IntVar(&concurrency, "concurrency", 8, "max config files assessed in parallel")
	flag.BoolVar(&listRules, "list-rules", false, "list the registered rules and exit")
	flag.StringVar(&projectRepo, "project", "", "repo path whose .mcp.json (project scope) is compared against each config; reports name collisions and which scope wins (local > project > user)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mcpscan [flags] <config.json | glob> [more configs...]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Reject unknown values up front: a typo in -fail-on would otherwise look up
	// rank 0 and fail every CI run, and a bad -min-severity would show everything.
	minSev, ok := parseSeverity(minLevel)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown -min-severity %q (valid: info, low, medium, high)\n", minLevel)
		os.Exit(2)
	}
	gate := strings.ToLower(failOn)
	if gate != "" && !validGate(gate) {
		fmt.Fprintf(os.Stderr, "error: unknown -fail-on %q (valid: low, medium, high, critical)\n", failOn)
		os.Exit(2)
	}

	if listRules {
		for _, r := range Rules() {
			fmt.Println(r.ID)
		}
		return
	}

	paths, err := expandPaths(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(paths) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	opts := []Option{WithConcurrency(concurrency)}
	if projectRepo != "" {
		opts = append(opts, WithProjectRepo(projectRepo))
	}
	scanner := NewScanner(opts...)
	reports, err := scanner.ScanFiles(context.Background(), paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	} else {
		for _, r := range reports {
			r.WriteText(os.Stdout, minSev)
		}
		if len(reports) > 1 {
			fmt.Printf("fleet verdict: %s (worst of %d configs)\n", WorstBand(reports), len(reports))
		}
	}

	if gate != "" && bandAtLeast(WorstBand(reports), gate) {
		os.Exit(3)
	}
}

// expandPaths turns positional args (files or globs) into a de-duplicated list of
// config file paths.
func expandPaths(args []string) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, a := range args {
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", a, err)
		}
		if matches == nil {
			matches = []string{a} // treat as a literal path; LoadConfig reports if missing
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				paths = append(paths, m)
			}
		}
	}
	return paths, nil
}

// parseSeverity maps a -min-severity value to a Severity; ok is false for an
// unknown value.
func parseSeverity(s string) (sev Severity, ok bool) {
	switch strings.ToLower(s) {
	case "high":
		return High, true
	case "medium":
		return Medium, true
	case "low":
		return Low, true
	case "info":
		return Info, true
	default:
		return Info, false
	}
}

var bandRank = map[string]int{"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// validGate reports whether band is a usable -fail-on value. "clean" is a real
// band but is rejected: every report is at least clean, so the gate would always fail.
func validGate(band string) bool {
	rank, ok := bandRank[band]
	return ok && rank > bandRank["clean"]
}

func bandAtLeast(got, threshold string) bool {
	return bandRank[got] >= bandRank[threshold]
}
