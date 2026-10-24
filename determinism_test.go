package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Go randomizes map iteration order on purpose, so any output built by ranging
// over a map can change between runs. These tests repeat the same input many
// times: with three keys a random order would differ from the first run in
// almost every attempt, so a flaky implementation fails, not passes by luck.
const repeats = 50

func TestSecretInEnvOrderIsDeterministic(t *testing.T) {
	cfg := &Config{MCPServers: map[string]Server{
		"api": {
			Command: "npx",
			Args:    []string{"-y", "some-server@1.0.0"},
			Env:     map[string]string{"C_SECRET": "x", "A_API_KEY": "x", "B_TOKEN": "x"},
		},
	}}

	first, err := json.Marshal(Assess("synthetic", cfg))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < repeats; i++ {
		got, err := json.Marshal(Assess("synthetic", cfg))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(first) {
			t.Fatalf("run %d: JSON differs from run 0\nrun 0: %s\nrun %d: %s", i, first, i, got)
		}
	}

	// Same-severity findings keep the env vars' sorted order.
	var vars []string
	for _, f := range Evaluate("api", cfg.MCPServers["api"]) {
		if f.Rule == "SECRET_IN_ENV" {
			v, _, _ := strings.Cut(strings.TrimPrefix(f.Detail, "Env var "), " looks like")
			vars = append(vars, v)
		}
	}
	if strings.Join(vars, ",") != "A_API_KEY,B_TOKEN,C_SECRET" {
		t.Errorf("SECRET_IN_ENV order = %v, want sorted by env var name", vars)
	}
}

// A name matching several sensitive keys must give the same reason every run:
// the first match in the fixed list wins, whatever order the name spells them.
// "slack" is listed before "postgres", so it wins here.
func TestDataSensitiveReasonIsDeterministic(t *testing.T) {
	const name = "postgres-slack"
	want := "Name suggests access to internal messages."
	for i := 0; i < repeats; i++ {
		var detail string
		for _, f := range Evaluate(name, Server{Command: "npx"}) {
			if f.Rule == "DATA_SENSITIVE" {
				detail = f.Detail
			}
		}
		if !strings.HasPrefix(detail, want) {
			t.Fatalf("run %d: DATA_SENSITIVE detail = %q, want prefix %q", i, detail, want)
		}
	}
}
