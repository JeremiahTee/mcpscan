package main

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Scanner assesses one or more MCP config files. It is constructed with functional
// options so the zero-configuration case stays simple while leaving room to tune
// concurrency and severity filtering without breaking the constructor signature.
type Scanner struct {
	concurrency int
	projectRepo string // optional repo whose .mcp.json is compared (project scope)
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithConcurrency bounds how many config files are assessed in parallel.
// Values below 1 fall back to 1.
func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		if n < 1 {
			n = 1
		}
		s.concurrency = n
	}
}

// NewScanner builds a Scanner with the given options.
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{concurrency: 8}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ScanFiles assesses each config path concurrently and returns one Report per
// path, in the same order as the input. The scan is bounded by the configured
// concurrency and cancellable via ctx: the first parse error cancels the rest and
// is returned. This is the fan-out/fan-in pattern with a shared-nothing result
// slice — each goroutine writes only its own index, so no lock is needed.
func (sc *Scanner) ScanFiles(ctx context.Context, paths []string) ([]Report, error) {
	reports := make([]Report, len(paths))

	// The .mcp.json is read once and shared read-only by every goroutine.
	var repo *ProjectFile
	if sc.projectRepo != "" {
		var err error
		if repo, err = LoadProjectFile(sc.projectRepo); err != nil {
			return nil, err
		}
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(sc.concurrency)

	for i, path := range paths {
		i, path := i, path // capture per-iteration (safe on all Go versions)
		g.Go(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				return err
			}
			cfg.Repo = repo
			reports[i] = Assess(path, cfg)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return reports, nil
}

// WorstBand returns the highest risk band across a set of reports, for a fleet-wide
// verdict and CI gating.
func WorstBand(reports []Report) string {
	worst := 0
	for _, r := range reports {
		if bandRank[r.OverallBand] > worst {
			worst = bandRank[r.OverallBand]
		}
	}
	for name, rank := range bandRank {
		if rank == worst {
			return name
		}
	}
	return "clean"
}
