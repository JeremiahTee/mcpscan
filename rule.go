package main

// Severity ranks a finding. Weights feed the per-server risk score.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// weight is the point contribution of a finding to a server's risk score.
func (s Severity) weight() int {
	switch s {
	case High:
		return 40
	case Medium:
		return 20
	case Low:
		return 10
	default:
		return 0
	}
}

// Finding is one explainable risk signal against a single server. Every finding
// carries the reason it fired so the report is auditable rather than a bare score.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	Level    string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Good     bool     `json:"good,omitempty"`
}

// Rule is one auditable check against a single MCP server. Rules are the unit of
// extension: a new risk signal is a new Rule registered into the package registry,
// so the scanner is open for extension without modifying the evaluation engine.
type Rule struct {
	ID    string
	Check func(name string, s Server) []Finding
}

// registry holds every rule the scanner will run. Rules self-register from their
// own files via Register in an init function, keeping each rule's definition and
// its registration in one place.
var registry []Rule

// Register adds a rule to the package registry. It is called from init functions.
func Register(r Rule) { registry = append(registry, r) }

// Rules returns the registered rules (used by --list-rules and tests).
func Rules() []Rule { return registry }

// Evaluate runs every registered rule against a server and returns all findings,
// with each finding's display level filled in.
func Evaluate(name string, s Server) []Finding {
	var out []Finding
	for _, r := range registry {
		out = append(out, r.Check(name, s)...)
	}
	for i := range out {
		out[i].Level = out[i].Severity.String()
	}
	return out
}
