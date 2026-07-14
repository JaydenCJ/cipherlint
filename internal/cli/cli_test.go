// In-process CLI integration tests: real files on disk, real argument
// vectors, asserted stdout/stderr and exit codes — everything but the
// process boundary, which scripts/smoke.sh covers.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/version"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const cleanNginx = `server {
    listen 443 ssl;
    server_name good.example.test;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
}
`

const legacyNginx = `server {
    listen 443 ssl;
    server_name bad.example.test;
    ssl_protocols SSLv3 TLSv1 TLSv1.2;
    ssl_ciphers RC4-SHA:DES-CBC3-SHA:AES128-SHA;
}
`

func TestVersionSubcommand(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-V"} {
		code, out, _ := run(t, arg)
		if code != 0 || strings.TrimSpace(out) != "cipherlint "+version.Version {
			t.Fatalf("%s: code=%d out=%q", arg, code, out)
		}
	}
}

func TestHelpAndNoArgs(t *testing.T) {
	code, out, _ := run(t, "--help")
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("--help: code=%d out=%q", code, out)
	}
	code, _, errOut := run(t)
	if code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no args: code=%d err=%q", code, errOut)
	}
}

func TestLintCleanConfigExitsZero(t *testing.T) {
	path := writeFile(t, "nginx.conf", cleanNginx)
	code, out, errOut := run(t, "lint", path)
	if code != 0 {
		t.Fatalf("clean config should exit 0, got %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "0 errors, 0 warnings") {
		t.Fatalf("summary wrong: %s", out)
	}
	// `cipherlint <file>` behaves exactly like `cipherlint lint <file>`.
	codeBare, outBare, _ := run(t, path)
	if codeBare != code || outBare != out {
		t.Fatal("bare invocation must equal the lint subcommand")
	}
}

func TestLintLegacyConfigExitsOne(t *testing.T) {
	path := writeFile(t, "nginx.conf", legacyNginx)
	code, out, _ := run(t, "lint", path)
	if code != 1 {
		t.Fatalf("legacy config should exit 1, got %d", code)
	}
	for _, want := range []string{"CL001", "CL004", "SSLv3", "RC4"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFailOnThreshold(t *testing.T) {
	// Clean of errors but carries an info (missing HSTS): exit 0 by
	// default, exit 1 with --fail-on info.
	src := strings.Replace(cleanNginx, "    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n", "", 1)
	path := writeFile(t, "nginx.conf", src)
	if code, _, _ := run(t, "lint", path); code != 0 {
		t.Fatalf("info-only findings should pass at default threshold, got %d", code)
	}
	if code, _, _ := run(t, "lint", "--fail-on", "info", path); code != 1 {
		t.Fatal("--fail-on info should fail on info findings")
	}
}

func TestJSONFormatIsParseable(t *testing.T) {
	path := writeFile(t, "nginx.conf", legacyNginx)
	_, out, _ := run(t, "lint", "--format", "json", path)
	var env struct {
		Tool     string `json:"tool"`
		Profile  string `json:"profile"`
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if env.Tool != "cipherlint" || env.Profile != "intermediate@2026-01" || len(env.Findings) == 0 {
		t.Fatalf("envelope wrong: %+v", env)
	}
	// And the third output format renders its table.
	_, md, _ := run(t, "lint", "--format", "markdown", path)
	if !strings.Contains(md, "| Location | Severity |") {
		t.Fatalf("markdown table missing:\n%s", md)
	}
}

func TestProfilePinning(t *testing.T) {
	src := cleanNginx + "\nserver { listen 443 ssl; ssl_stapling on; server_name s.example.test;\n add_header Strict-Transport-Security \"max-age=63072000\"; }\n"
	path := writeFile(t, "nginx.conf", src)
	_, out2026, _ := run(t, "lint", "-p", "intermediate@2026-01", "--fail-on", "info", path)
	_, out2023, _ := run(t, "lint", "-p", "intermediate@2023-10", "--fail-on", "info", path)
	if !strings.Contains(out2026, "CL013") {
		t.Fatalf("2026 table should flag stapling on:\n%s", out2026)
	}
	if strings.Contains(out2023, "CL013") {
		t.Fatalf("2023 table should accept stapling on:\n%s", out2023)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	path := writeFile(t, "nginx.conf", cleanNginx)
	cases := [][]string{
		{"lint", "--format", "yaml", path},
		{"lint", "--fail-on", "fatal", path},
		{"lint", "--server", "iis", path},
		{"lint", "--bogus-flag", path},
		{"lint", "-p", "paranoid", path},
	}
	for _, args := range cases {
		if code, _, _ := run(t, args...); code != 2 {
			t.Fatalf("%v should exit 2, got %d", args, code)
		}
	}
}

func TestRuntimeErrorsExitThree(t *testing.T) {
	// Unreadable file.
	code, _, errOut := run(t, "lint", filepath.Join(t.TempDir(), "absent.conf"))
	if code != 3 || errOut == "" {
		t.Fatalf("missing file: code=%d err=%q", code, errOut)
	}
	// Undetectable dialect, with a hint toward --server.
	path := writeFile(t, "mystery.txt", "hello world\n")
	code, _, errOut = run(t, "lint", path)
	if code != 3 || !strings.Contains(errOut, "--server") {
		t.Fatalf("undetectable: code=%d err=%q", code, errOut)
	}
}

func TestServerFlagOverridesDetection(t *testing.T) {
	// The same bare directives parse as nginx when forced.
	path := writeFile(t, "mystery.txt", "ssl_protocols TLSv1.2 TLSv1.3;\n")
	code, out, errOut := run(t, "lint", "--server", "nginx", path)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "1 server, 1 file") {
		t.Fatalf("expected one file-scope server:\n%s", out)
	}
}

func TestMultipleFilesAggregate(t *testing.T) {
	a := writeFile(t, "a.conf", cleanNginx)
	b := writeFile(t, "haproxy.cfg", "frontend f\n    bind :443 ssl crt /x.pem\n    http-response set-header Strict-Transport-Security \"max-age=63072000\"\n")
	code, out, errOut := run(t, "lint", a, b)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "2 servers, 2 files") {
		t.Fatalf("aggregate summary wrong:\n%s", out)
	}
}

func TestProfilesSubcommand(t *testing.T) {
	code, out, _ := run(t, "profiles")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{"modern@2026-01", "intermediate@2023-10", "old@2026-01", "Mozilla"} {
		if !strings.Contains(out, want) {
			t.Fatalf("profiles output missing %q:\n%s", want, out)
		}
	}
	code, out, _ = run(t, "profiles", "--format", "json")
	if code != 0 {
		t.Fatalf("json code=%d", code)
	}
	var rows []map[string]string
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 6 {
		t.Fatalf("profiles --format json: err=%v rows=%d", err, len(rows))
	}
}

func TestExplainSubcommand(t *testing.T) {
	code, out, _ := run(t, "explain", "cl013")
	if code != 0 || !strings.Contains(out, "OCSP") || !strings.Contains(out, "Citations:") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, _, errOut := run(t, "explain", "CL999")
	if code != 2 || !strings.Contains(errOut, "CL001") {
		t.Fatalf("unknown rule: code=%d err=%q", code, errOut)
	}
}
