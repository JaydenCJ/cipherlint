// Package cli wires the subcommands: lint (the default), profiles, explain
// and version. Flag parsing is hand-rolled so exit codes stay exact: 0 clean,
// 1 findings at/above --fail-on, 2 usage error, 3 runtime error.
package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/lint"
	"github.com/JaydenCJ/cipherlint/internal/model"
	"github.com/JaydenCJ/cipherlint/internal/parse"
	"github.com/JaydenCJ/cipherlint/internal/policy"
	"github.com/JaydenCJ/cipherlint/internal/render"
	"github.com/JaydenCJ/cipherlint/internal/version"
)

const usage = `cipherlint — lint TLS configs against dated best-practice profiles, offline

Usage:
  cipherlint [lint] [flags] <config-file>...
  cipherlint profiles [--format text|json]
  cipherlint explain <rule-id>
  cipherlint version

Flags (lint):
  -p, --profile <name[@date]>   policy profile (default intermediate, newest date)
      --server <dialect>        nginx | apache | haproxy | caddy (default: auto-detect)
      --format <fmt>            text | json | markdown (default text)
      --fail-on <severity>      error | warning | info — exit 1 threshold (default error)

Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error, 3 runtime error.
`

// Run executes cipherlint and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "cipherlint %s\n", version.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "profiles":
		return runProfiles(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	default:
		return runLint(args, stdout, stderr)
	}
}

type lintOpts struct {
	profile string
	server  string
	format  string
	failOn  string
	files   []string
}

func parseLintArgs(args []string, stderr io.Writer) (lintOpts, bool) {
	o := lintOpts{profile: "intermediate", format: "text", failOn: lint.Error}
	usageErr := func(format string, a ...any) (lintOpts, bool) {
		fmt.Fprintf(stderr, "cipherlint: "+format+"\n", a...)
		fmt.Fprint(stderr, usage)
		return o, false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, bool) {
			if j := strings.IndexByte(a, '='); j >= 0 {
				return a[j+1:], true
			}
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		name := a
		if j := strings.IndexByte(a, '='); j >= 0 {
			name = a[:j]
		}
		switch name {
		case "-p", "--profile":
			v, ok := val()
			if !ok {
				return usageErr("%s needs a value", name)
			}
			o.profile = v
		case "--server":
			v, ok := val()
			if !ok {
				return usageErr("--server needs a value")
			}
			valid := false
			for _, f := range parse.Formats {
				if v == f {
					valid = true
				}
			}
			if !valid {
				return usageErr("unknown --server %q (choose from %s)", v, strings.Join(parse.Formats, ", "))
			}
			o.server = v
		case "--format":
			v, ok := val()
			if !ok || (v != "text" && v != "json" && v != "markdown") {
				return usageErr("unknown --format %q (text, json, markdown)", v)
			}
			o.format = v
		case "--fail-on":
			v, ok := val()
			if !ok || (v != lint.Error && v != lint.Warning && v != lint.Info) {
				return usageErr("unknown --fail-on %q (error, warning, info)", v)
			}
			o.failOn = v
		default:
			if strings.HasPrefix(name, "-") {
				return usageErr("unknown flag %q", name)
			}
			o.files = append(o.files, a)
		}
	}
	if len(o.files) == 0 {
		return usageErr("no config files given")
	}
	return o, true
}

func runLint(args []string, stdout, stderr io.Writer) int {
	o, ok := parseLintArgs(args, stderr)
	if !ok {
		return 2
	}
	prof, err := policy.Resolve(o.profile)
	if err != nil {
		fmt.Fprintf(stderr, "cipherlint: %v\n", err)
		return 2
	}

	var servers []model.Server
	var files []string
	for _, path := range o.files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "cipherlint: %v\n", err)
			return 3
		}
		src := string(data)
		format := o.server
		if format == "" {
			format = parse.Detect(path, src)
			if format == "" {
				fmt.Fprintf(stderr, "cipherlint: cannot detect the config dialect of %s; pass --server nginx|apache|haproxy|caddy\n", path)
				return 3
			}
		}
		found := parse.Parse(format, path, src)
		if len(found) == 0 {
			fmt.Fprintf(stderr, "cipherlint: %s: no TLS server contexts found (parsed as %s)\n", path, format)
			return 3
		}
		servers = append(servers, found...)
		files = append(files, path)
	}

	findings := lint.Run(servers, prof)
	report := render.Report{Profile: prof.ID(), Files: files, Servers: len(servers), Findings: findings}
	switch o.format {
	case "json":
		fmt.Fprint(stdout, render.JSON(report))
	case "markdown":
		fmt.Fprint(stdout, render.Markdown(report))
	default:
		fmt.Fprint(stdout, render.Text(report))
	}
	if lint.AtOrAbove(findings, o.failOn) {
		return 1
	}
	return 0
}

func runProfiles(args []string, stdout, stderr io.Writer) int {
	format := "text"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		} else if v, ok := strings.CutPrefix(args[i], "--format="); ok {
			format = v
		} else {
			fmt.Fprintf(stderr, "cipherlint: unknown argument %q\n", args[i])
			return 2
		}
	}
	profiles := policy.List()
	if format == "json" {
		var b strings.Builder
		b.WriteString("[\n")
		for i, p := range profiles {
			fmt.Fprintf(&b, "  {\"profile\": %q, \"min_version\": %q, \"source\": %q}", p.ID(), p.MinVersion.String(), p.Source)
			if i < len(profiles)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("]\n")
		fmt.Fprint(stdout, b.String())
		return 0
	}
	if format != "text" {
		fmt.Fprintf(stderr, "cipherlint: unknown --format %q (text, json)\n", format)
		return 2
	}
	fmt.Fprintf(stdout, "%-24s %-9s %-6s %-6s %s\n", "PROFILE", "MIN", "AEAD", "FS", "SOURCE")
	for _, p := range profiles {
		fmt.Fprintf(stdout, "%-24s %-9s %-6s %-6s %s\n",
			p.ID(), p.MinVersion, yn(p.RequireAEAD), yn(p.RequireFS), p.Source)
	}
	fmt.Fprintf(stdout, "\nBare names resolve to the newest date; pin with name@date (e.g. intermediate@2023-10).\n")
	return 0
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "cipherlint: explain takes exactly one rule ID (e.g. CL004)\n")
		return 2
	}
	id := strings.ToUpper(args[0])
	doc, ok := lint.Doc(id)
	if !ok {
		var ids []string
		for _, r := range lint.Rules {
			ids = append(ids, r.ID)
		}
		sort.Strings(ids)
		fmt.Fprintf(stderr, "cipherlint: unknown rule %q (known: %s)\n", id, strings.Join(ids, ", "))
		return 2
	}
	fmt.Fprintf(stdout, "%s — %s\n\n%s\n\nCitations: %s\n", doc.ID, doc.Title, doc.Summary, doc.Citation)
	return 0
}
