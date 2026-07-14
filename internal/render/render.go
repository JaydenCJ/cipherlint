// Package render turns findings into the three output formats: aligned
// text for terminals, stable JSON (schema_version 1) for machines, and
// Markdown tables for PR comments. All three are deterministic: same
// findings in, byte-identical output out.
package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/lint"
	"github.com/JaydenCJ/cipherlint/internal/version"
)

// Report bundles everything a renderer needs.
type Report struct {
	Profile  string // fully-qualified, e.g. "intermediate@2026-01"
	Files    []string
	Servers  int
	Findings []lint.Finding
}

func (r Report) counts() (errors, warnings, infos int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case lint.Error:
			errors++
		case lint.Warning:
			warnings++
		case lint.Info:
			infos++
		}
	}
	return
}

// Summary renders the one-line totals shared by text and markdown output.
func (r Report) Summary() string {
	e, w, i := r.counts()
	return fmt.Sprintf("%s, %s, %d info — profile %s, %s, %s",
		plural(e, "error"), plural(w, "warning"), i, r.Profile,
		plural(r.Servers, "server"), plural(len(r.Files), "file"))
}

// plural formats "1 error" / "2 errors" — counts of one drop the s.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// Text renders the human format: one aligned line per finding with location,
// severity, rule and citation, then the summary.
func Text(r Report) string {
	var b strings.Builder
	locWidth, sevWidth := 0, 0
	locs := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		locs[i] = loc
		if len(loc) > locWidth {
			locWidth = len(loc)
		}
		if len(f.Severity) > sevWidth {
			sevWidth = len(f.Severity)
		}
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "%-*s  %-*s  %s  %s [%s]\n",
			locWidth, locs[i], sevWidth, f.Severity, f.Rule, f.Message, f.Citation)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "no findings\n")
	}
	fmt.Fprintf(&b, "%s\n", r.Summary())
	return b.String()
}

// jsonReport is the stable machine envelope. schema_version only changes on
// breaking shape changes.
type jsonReport struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	SchemaVersion int            `json:"schema_version"`
	Profile       string         `json:"profile"`
	Files         []string       `json:"files"`
	Servers       int            `json:"servers"`
	Findings      []lint.Finding `json:"findings"`
	Summary       map[string]int `json:"summary"`
}

// JSON renders the machine format.
func JSON(r Report) string {
	e, w, i := r.counts()
	files := append([]string(nil), r.Files...)
	sort.Strings(files)
	findings := r.Findings
	if findings == nil {
		findings = []lint.Finding{}
	}
	env := jsonReport{
		Tool: "cipherlint", Version: version.Version, SchemaVersion: 1,
		Profile: r.Profile, Files: files, Servers: r.Servers, Findings: findings,
		Summary: map[string]int{"errors": e, "warnings": w, "infos": i},
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		// Findings are plain strings and ints; marshaling cannot fail.
		panic(err)
	}
	return string(out) + "\n"
}

// Markdown renders a PR-comment-ready table.
func Markdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### cipherlint — %s\n\n", r.Profile)
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n\n")
	} else {
		b.WriteString("| Location | Severity | Rule | Finding | Citation |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				loc, f.Severity, f.Rule, mdEscape(f.Message), mdEscape(f.Citation))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%s\n", r.Summary())
	return b.String()
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
