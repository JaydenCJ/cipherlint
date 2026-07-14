// Lint engine tests. Each test builds a minimal normalized server, runs one
// profile over it, and asserts on the exact rules that fire — this is the
// contract the README's rule table documents.
package lint

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
	"github.com/JaydenCJ/cipherlint/internal/policy"
)

func prof(t *testing.T, spec string) policy.Profile {
	t.Helper()
	p, err := policy.Resolve(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// srv builds a baseline healthy nginx-style server the tests then degrade.
func srv() model.Server {
	return model.Server{
		Format: "nginx", Name: "s.example.test", File: "nginx.conf", Line: 1,
		CipherDialect: model.DialectOpenSSL,
		Protocols:     model.Explicit([]model.Version{model.TLS12, model.TLS13}, 2),
		HSTS:          model.Explicit(model.HSTS{MaxAge: 63072000}, 3),
	}
}

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule+":"+f.Severity)
	}
	return out
}

func has(fs []Finding, rule, severity string) bool {
	for _, f := range fs {
		if f.Rule == rule && (severity == "" || f.Severity == severity) {
			return true
		}
	}
	return false
}

func TestObsoleteProtocolIsError(t *testing.T) {
	s := srv()
	s.Protocols = model.Explicit([]model.Version{model.TLS10, model.TLS12, model.TLS13}, 2)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL001", Error) {
		t.Fatalf("TLS 1.0 must be a CL001 error: %v", rules(fs))
	}
}

func TestOldProfileDowngradesTLS10ButNotSSLv3(t *testing.T) {
	// The `old` profile documents a legacy-client fleet, so TLS 1.0 is a
	// warning there — but never silent, and SSLv3 stays an error everywhere.
	s := srv()
	s.Protocols = model.Explicit([]model.Version{model.TLS10, model.TLS12, model.TLS13}, 2)
	fs := Run([]model.Server{s}, prof(t, "old"))
	if !has(fs, "CL001", Warning) || has(fs, "CL001", Error) {
		t.Fatalf("old profile should warn, not error: %v", rules(fs))
	}
	s.Protocols = model.Explicit([]model.Version{model.SSLv3, model.TLS12, model.TLS13}, 2)
	fs = Run([]model.Server{s}, prof(t, "old"))
	if !has(fs, "CL001", Error) {
		t.Fatalf("SSLv3 is an error under every profile: %v", rules(fs))
	}
}

func TestModernProfileFlagsTLS12(t *testing.T) {
	fs := Run([]model.Server{srv()}, prof(t, "modern"))
	if !has(fs, "CL002", Warning) {
		t.Fatalf("TLS 1.2 under modern must warn: %v", rules(fs))
	}
	// The same server is clean under intermediate.
	fs = Run([]model.Server{srv()}, prof(t, "intermediate"))
	if has(fs, "CL002", "") {
		t.Fatalf("TLS 1.2 under intermediate must not warn: %v", rules(fs))
	}
}

func TestMissingTLS13Warns(t *testing.T) {
	s := srv()
	s.Protocols = model.Explicit([]model.Version{model.TLS12}, 2)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL003", Warning) {
		t.Fatalf("missing TLS 1.3 must warn: %v", rules(fs))
	}
}

func TestBrokenCipherCategories(t *testing.T) {
	s := srv()
	s.Ciphers = model.Explicit("RC4-SHA:DES-CBC3-SHA:NULL-SHA:ADH-AES128-SHA:EXP-RC4-MD5:DES-CBC-SHA", 4)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	count := 0
	for _, f := range fs {
		if f.Rule == "CL004" {
			if f.Severity != Error {
				t.Fatalf("CL004 must be error: %+v", f)
			}
			count++
		}
	}
	// One finding per category: NULL, anon, export, DES, RC4, 3DES.
	if count != 6 {
		t.Fatalf("expected 6 CL004 category findings, got %d: %v", count, rules(fs))
	}
}

func TestStaticRSAKeyExchange(t *testing.T) {
	s := srv()
	s.Ciphers = model.Explicit("AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256", 4)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL006", Error) {
		t.Fatalf("static RSA under intermediate must error: %v", rules(fs))
	}
	// Under `old`, forward secrecy is not required: info only.
	fs = Run([]model.Server{s}, prof(t, "old"))
	if !has(fs, "CL006", Info) || has(fs, "CL006", Error) {
		t.Fatalf("static RSA under old must be info: %v", rules(fs))
	}
	// The same weakness written in Caddy's IANA dialect is caught too.
	s.CipherDialect = model.DialectIANA
	s.Ciphers = model.Explicit("TLS_RSA_WITH_AES_128_CBC_SHA TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 4)
	fs = Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL006", Error) {
		t.Fatalf("IANA-name static-RSA suite must be caught: %v", rules(fs))
	}
}

func TestCBCOnlyFlaggedWhereAEADRequired(t *testing.T) {
	s := srv()
	s.Ciphers = model.Explicit("ECDHE-RSA-AES128-SHA256", 4)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL005", Warning) {
		t.Fatalf("CBC under intermediate must warn: %v", rules(fs))
	}
	if fs := Run([]model.Server{s}, prof(t, "old")); has(fs, "CL005", "") {
		t.Fatalf("CBC under old must pass: %v", rules(fs))
	}
}

func TestCipherLintSkippedOnTLS13OnlyServer(t *testing.T) {
	// A TLS 1.3-only endpoint cannot negotiate any TLS 1.2 suite; a legacy
	// cipher list is dead config, not a vulnerability.
	s := srv()
	s.Protocols = model.Explicit([]model.Version{model.TLS13}, 2)
	s.Ciphers = model.Explicit("RC4-SHA", 4)
	fs := Run([]model.Server{s}, prof(t, "modern"))
	if has(fs, "CL004", "") {
		t.Fatalf("cipher list on TLS 1.3-only server should not fire: %v", rules(fs))
	}
}

func TestEmptyCipherListIsError(t *testing.T) {
	s := srv()
	s.Ciphers = model.Explicit("HIGH:!HIGH", 4)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL015", Error) {
		t.Fatalf("zero-suite list must be CL015: %v", rules(fs))
	}
}

func TestUnknownAndTLS13TokensAreInfo(t *testing.T) {
	s := srv()
	s.Ciphers = model.Explicit("ECDHE-RSA-AES128-GCM-SHA256:BOGUS:TLS_AES_128_GCM_SHA256", 4)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	n := 0
	for _, f := range fs {
		if f.Rule == "CL014" {
			if f.Severity != Info {
				t.Fatalf("CL014 must be info: %+v", f)
			}
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 CL014 findings (typo + 1.3 name), got %d: %v", n, rules(fs))
	}
}

func TestServerPreferenceBothDirections(t *testing.T) {
	s := srv()
	s.PreferServer = model.Explicit(true, 5)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL007", Info) {
		t.Fatalf("server-preference on under intermediate: %v", rules(fs))
	}
	s.PreferServer = model.Explicit(false, 5)
	if fs := Run([]model.Server{s}, prof(t, "old")); !has(fs, "CL007", Info) {
		t.Fatalf("server-preference off under old: %v", rules(fs))
	}
	// Implicit defaults never fire CL007.
	s.PreferServer = model.Default(true)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); has(fs, "CL007", "") {
		t.Fatalf("implicit preference must not fire: %v", rules(fs))
	}
}

func TestSessionTicketsExplicitOnWarns(t *testing.T) {
	s := srv()
	s.SessionTicket = model.Explicit(true, 6)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL008", Warning) {
		t.Fatalf("explicit tickets on: %v", rules(fs))
	}
	s.SessionTicket = model.Default(true)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); has(fs, "CL008", "") {
		t.Fatalf("implicit tickets must not fire: %v", rules(fs))
	}
}

func TestStaplingAdviceFlipsWithTableDate(t *testing.T) {
	// The flagship dated-table behavior: same directive, opposite advice
	// depending on which vintage you lint against.
	s := srv()
	s.Stapling = model.Explicit(true, 7)
	if fs := Run([]model.Server{s}, prof(t, "intermediate@2023-10")); has(fs, "CL013", "") {
		t.Fatalf("stapling on matches 2023 advice: %v", rules(fs))
	}
	if fs := Run([]model.Server{s}, prof(t, "intermediate@2026-01")); !has(fs, "CL013", Info) {
		t.Fatalf("stapling on contradicts 2026 advice: %v", rules(fs))
	}
	s.Stapling = model.Explicit(false, 7)
	if fs := Run([]model.Server{s}, prof(t, "intermediate@2023-10")); !has(fs, "CL013", Info) {
		t.Fatalf("stapling off contradicts 2023 advice: %v", rules(fs))
	}
	if fs := Run([]model.Server{s}, prof(t, "intermediate@2026-01")); has(fs, "CL013", "") {
		t.Fatalf("stapling off matches 2026 advice: %v", rules(fs))
	}
}

func TestWeakDHParameters(t *testing.T) {
	s := srv()
	s.DHBits = model.Explicit(1024, 8)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL009", Error) {
		t.Fatalf("1024-bit DH must error: %v", rules(fs))
	}
	s.DHBits = model.Explicit(2048, 8)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); has(fs, "CL009", "") {
		t.Fatalf("2048-bit DH must pass: %v", rules(fs))
	}
}

func TestCurveFindings(t *testing.T) {
	s := srv()
	s.Curves = model.Explicit([]string{"secp192r1", "secp521r1", "X25519"}, 9)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	if !has(fs, "CL010", Error) {
		t.Fatalf("secp192r1 must error: %v", rules(fs))
	}
	if !has(fs, "CL010", Info) {
		t.Fatalf("secp521r1 outside the recommended set must info: %v", rules(fs))
	}
}

func TestHSTSMissingAndShort(t *testing.T) {
	s := srv()
	s.HSTS = model.Setting[model.HSTS]{}
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL011", Info) {
		t.Fatalf("missing HSTS must info: %v", rules(fs))
	}
	s = srv()
	s.HSTS = model.Explicit(model.HSTS{MaxAge: 300}, 3)
	if fs := Run([]model.Server{s}, prof(t, "intermediate")); !has(fs, "CL012", Warning) {
		t.Fatalf("short max-age must warn: %v", rules(fs))
	}
}

func TestCiphersuitesNameValidation(t *testing.T) {
	s := srv()
	s.Ciphersuites = model.Explicit([]string{"TLS_AES_256_GCM_SHA384", "NOT_A_SUITE"}, 10)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	n := 0
	for _, f := range fs {
		if f.Rule == "CL014" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("exactly the bogus 1.3 name should fire CL014: %v", rules(fs))
	}
}

func TestFindingsSortedAndCited(t *testing.T) {
	s := srv()
	s.Protocols = model.Explicit([]model.Version{model.TLS10, model.TLS12}, 9)
	s.Ciphers = model.Explicit("RC4-SHA", 2)
	fs := Run([]model.Server{s}, prof(t, "intermediate"))
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Line > fs[i].Line {
			t.Fatalf("findings not sorted by line: %v", rules(fs))
		}
	}
	for _, f := range fs {
		if strings.TrimSpace(f.Citation) == "" {
			t.Fatalf("finding %s has no citation", f.Rule)
		}
	}
	// Severity helpers, which --fail-on builds on.
	two := []Finding{{Severity: Info}, {Severity: Warning}}
	if MaxSeverity(two) != Warning {
		t.Fatalf("MaxSeverity = %s", MaxSeverity(two))
	}
	if !AtOrAbove(two, Warning) || AtOrAbove(two, Error) {
		t.Fatal("AtOrAbove thresholds wrong")
	}
	if MaxSeverity(nil) != "" || AtOrAbove(nil, Info) {
		t.Fatal("empty findings must be below every threshold")
	}
}

func TestEveryRuleHasCatalogEntry(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] {
			t.Fatalf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		if r.Citation == "" || r.Summary == "" || r.Title == "" {
			t.Fatalf("rule %s is missing catalog fields", r.ID)
		}
	}
	if len(Rules) != 15 {
		t.Fatalf("catalog has %d rules, want 15 (CL001-CL015)", len(Rules))
	}
}
