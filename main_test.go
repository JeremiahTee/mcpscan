package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain lets a test re-run this binary as the mcpscan command: when
// MCPSCAN_RUN_MAIN is set, it calls main() with the given args instead of
// running the tests. That is how the tests below see real exit codes, which
// os.Exit would otherwise take down with the test process.
func TestMain(m *testing.M) {
	if os.Getenv("MCPSCAN_RUN_MAIN") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runMain runs mcpscan with args in a child process and returns its exit code
// and stderr.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "MCPSCAN_RUN_MAIN=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String()
	default:
		t.Fatalf("run mcpscan %v: %v", args, err)
		return 0, ""
	}
}

func TestFailOnRejectsUnknownBand(t *testing.T) {
	code, stderr := runMain(t, "-fail-on", "hgih", "examples/sample.mcp.json")
	if code != 2 {
		t.Fatalf("-fail-on hgih: exit %d, want 2 (usage error); stderr: %s", code, stderr)
	}
	for _, band := range []string{"low", "medium", "high", "critical"} {
		if !strings.Contains(stderr, band) {
			t.Errorf("stderr should list valid band %q; got: %s", band, stderr)
		}
	}
}

// "clean" is a real band, but every report reaches it, so as a gate it would
// fail every run; it is rejected like a typo.
func TestFailOnRejectsClean(t *testing.T) {
	if code, stderr := runMain(t, "-fail-on", "clean", "examples/sample.mcp.json"); code != 2 {
		t.Fatalf("-fail-on clean: exit %d, want 2; stderr: %s", code, stderr)
	}
}

// Flags are validated before any file is read: with a missing config, a bad
// flag must still be a usage error (2), not a read error (1).
func TestBadFlagCheckedBeforeFiles(t *testing.T) {
	for _, args := range [][]string{
		{"-fail-on", "hgih", "testdata/does-not-exist.json"},
		{"-min-severity", "loud", "testdata/does-not-exist.json"},
	} {
		if code, stderr := runMain(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2; stderr: %s", args, code, stderr)
		}
	}
}

func TestMinSeverityRejectsUnknownLevel(t *testing.T) {
	code, stderr := runMain(t, "-min-severity", "loud", "examples/sample.mcp.json")
	if code != 2 {
		t.Fatalf("-min-severity loud: exit %d, want 2 (usage error); stderr: %s", code, stderr)
	}
	for _, level := range []string{"info", "low", "medium", "high"} {
		if !strings.Contains(stderr, level) {
			t.Errorf("stderr should list valid level %q; got: %s", level, stderr)
		}
	}
}

// The sample config is critical, so a valid -fail-on band at or below it must
// still trip the gate (exit 3), in any letter case.
func TestFailOnValidBandStillGates(t *testing.T) {
	for _, band := range []string{"high", "HIGH", "critical"} {
		if code, stderr := runMain(t, "-fail-on", band, "examples/sample.mcp.json"); code != 3 {
			t.Errorf("-fail-on %s: exit %d, want 3; stderr: %s", band, code, stderr)
		}
	}
}

func TestValidMinSeverityRuns(t *testing.T) {
	for _, level := range []string{"info", "low", "MEDIUM", "high"} {
		if code, stderr := runMain(t, "-min-severity", level, "examples/sample.mcp.json"); code != 0 {
			t.Errorf("-min-severity %s: exit %d, want 0; stderr: %s", level, code, stderr)
		}
	}
}
