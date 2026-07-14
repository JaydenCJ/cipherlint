// Renderer tests: byte-determinism, JSON schema stability, and the shapes
// downstream consumers (CI pipelines, PR bots) rely on.
package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/lint"
)

func sample() Report {
	return Report{
		Profile: "intermediate@2026-01",
		Files:   []string{"nginx.conf"},
		Servers: 1,
		Findings: []lint.Finding{
			{Rule: "CL001", Severity: "error", File: "nginx.conf", Line: 3,
				Server: "a.example.test", Message: "TLS 1.0 is enabled", Citation: "RFC 8996 (2021-03)"},
			{Rule: "CL011", Severity: "info", File: "nginx.conf", Line: 1,
				Server: "a.example.test", Message: "no HSTS | header", Citation: "RFC 6797 (2012-11)"},
		},
	}
}

func TestTextContainsLocationsAndSummary(t *testing.T) {
	out := Text(sample())
	if !strings.Contains(out, "nginx.conf:3") || !strings.Contains(out, "CL001") {
		t.Fatalf("missing location or rule:\n%s", out)
	}
	// Counts of one must not read "1 errors" — pluralization is part of
	// the contract because the summary line lands in PR comments verbatim.
	if !strings.Contains(out, "1 error, 0 warnings, 1 info — profile intermediate@2026-01, 1 server, 1 file") {
		t.Fatalf("summary wrong:\n%s", out)
	}
	if !strings.Contains(out, "[RFC 8996 (2021-03)]") {
		t.Fatalf("citation missing:\n%s", out)
	}
	if out != Text(sample()) {
		t.Fatal("identical input must render byte-identically")
	}
}

func TestTextNoFindings(t *testing.T) {
	r := sample()
	r.Findings = nil
	out := Text(r)
	if !strings.Contains(out, "no findings") {
		t.Fatalf("clean report should say so:\n%s", out)
	}
}

func TestJSONEnvelopeShape(t *testing.T) {
	var env struct {
		Tool          string         `json:"tool"`
		Version       string         `json:"version"`
		SchemaVersion int            `json:"schema_version"`
		Profile       string         `json:"profile"`
		Findings      []lint.Finding `json:"findings"`
		Summary       map[string]int `json:"summary"`
	}
	if err := json.Unmarshal([]byte(JSON(sample())), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env.Tool != "cipherlint" || env.SchemaVersion != 1 || env.Version == "" {
		t.Fatalf("envelope wrong: %+v", env)
	}
	if len(env.Findings) != 2 || env.Summary["errors"] != 1 || env.Summary["infos"] != 1 {
		t.Fatalf("payload wrong: %+v", env)
	}
}

func TestJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	r := sample()
	r.Findings = nil
	out := JSON(r)
	if !strings.Contains(out, `"findings": []`) {
		t.Fatalf("empty findings must serialize as [], got:\n%s", out)
	}
}

func TestMarkdownTableAndEscaping(t *testing.T) {
	out := Markdown(sample())
	if !strings.Contains(out, "| Location | Severity | Rule | Finding | Citation |") {
		t.Fatalf("table header missing:\n%s", out)
	}
	// The '|' inside the message must be escaped or the table breaks.
	if !strings.Contains(out, `no HSTS \| header`) {
		t.Fatalf("pipe not escaped:\n%s", out)
	}
}
