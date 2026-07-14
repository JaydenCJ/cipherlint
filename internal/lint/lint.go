// Package lint applies a dated policy profile to normalized server configs
// and produces findings. The engine is pure: servers in, findings out, no
// I/O — which is what keeps every rule unit-testable and every run
// deterministic.
package lint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/ciphers"
	"github.com/JaydenCJ/cipherlint/internal/model"
	"github.com/JaydenCJ/cipherlint/internal/policy"
)

// Finding is one lint result, always carrying a citation.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Server   string `json:"server"`
	Message  string `json:"message"`
	Citation string `json:"citation"`
}

// Run lints every server against prof and returns findings sorted by file,
// line, then rule ID, so output is stable across runs.
func Run(servers []model.Server, prof policy.Profile) []Finding {
	var out []Finding
	for i := range servers {
		out = append(out, lintServer(&servers[i], prof)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out
}

// MaxSeverity returns the highest severity present, or "" for none.
func MaxSeverity(fs []Finding) string {
	best, bestRank := "", 0
	for _, f := range fs {
		if r := severityRank(f.Severity); r > bestRank {
			best, bestRank = f.Severity, r
		}
	}
	return best
}

// AtOrAbove reports whether any finding is at least the given severity.
func AtOrAbove(fs []Finding, sev string) bool {
	return severityRank(MaxSeverity(fs)) >= severityRank(sev)
}

func lintServer(s *model.Server, prof policy.Profile) []Finding {
	var out []Finding
	emit := func(rule, severity string, line int, format string, args ...any) {
		doc := ruleByID[rule]
		out = append(out, Finding{
			Rule: rule, Severity: severity, File: s.File, Line: line,
			Server: s.Name, Message: fmt.Sprintf(format, args...), Citation: doc.Citation,
		})
	}

	out = append(out, lintProtocols(s, prof)...)
	if hasPre13(s) {
		// TLS <= 1.2 cipher lists only matter if a pre-1.3 version can be
		// negotiated; on a TLS 1.3-only endpoint they are dead configuration.
		out = append(out, lintCipherList(s, prof)...)
	}
	out = append(out, lintCiphersuites(s)...)

	// CL007 — explicit cipher-order preference against the profile.
	if s.PreferServer.Set && !s.PreferServer.Implicit {
		switch {
		case prof.ServerPreference == policy.Off && s.PreferServer.Value:
			emit("CL007", Info, s.PreferServer.Line,
				"server-side cipher ordering is on; the %s profile lets the client choose among strong suites", prof.Name)
		case prof.ServerPreference == policy.On && !s.PreferServer.Value:
			emit("CL007", Info, s.PreferServer.Line,
				"server-side cipher ordering is off; the %s profile wants the server to enforce its order", prof.Name)
		}
	}

	// CL008 — session tickets explicitly on.
	if prof.SessionTickets == policy.Off && s.SessionTicket.Set &&
		!s.SessionTicket.Implicit && s.SessionTicket.Value {
		emit("CL008", Warning, s.SessionTicket.Line,
			"TLS session tickets are enabled; unrotated ticket keys defeat forward secrecy for resumed sessions")
	}

	// CL013 — OCSP stapling vs the table vintage.
	if s.Stapling.Set && !s.Stapling.Implicit {
		switch {
		case prof.OCSPStapling == policy.On && !s.Stapling.Value:
			emit("CL013", Info, s.Stapling.Line,
				"OCSP stapling is off; the %s@%s table recommends it on", prof.Name, prof.Date)
		case prof.OCSPStapling == policy.Retired && s.Stapling.Value:
			emit("CL013", Info, s.Stapling.Line,
				"OCSP stapling is on, but major CAs ended OCSP service in 2025 — the directive is now dead weight for most certificates")
		}
	}

	// CL009 — DH parameter size (knowable only for HAProxy's numeric tune).
	if s.DHBits.Set && s.DHBits.Value < prof.MinDHBits {
		emit("CL009", Error, s.DHBits.Line,
			"ephemeral DH parameters are %d bits; %d is the minimum (Logjam-class attacks reach 1024-bit groups)",
			s.DHBits.Value, prof.MinDHBits)
	}

	out = append(out, lintCurves(s, prof)...)
	out = append(out, lintHSTS(s, prof)...)
	return out
}

func hasPre13(s *model.Server) bool {
	if !s.Protocols.Set {
		return true // unknown protocol set: assume cipher list matters
	}
	for _, v := range s.Protocols.Value {
		if v < model.TLS13 {
			return true
		}
	}
	return false
}

func lintProtocols(s *model.Server, prof policy.Profile) []Finding {
	var out []Finding
	if !s.Protocols.Set {
		return nil
	}
	note := ""
	if s.Protocols.Implicit {
		note = implicitNote(s)
	}
	doc001 := ruleByID["CL001"]
	doc002 := ruleByID["CL002"]
	for _, v := range s.Protocols.Value {
		if v <= model.TLS11 {
			// Below TLS 1.2 is CL001. The `old` profile documents legacy
			// clients, so TLS 1.0/1.1 downgrade to warnings there — but the
			// SSL protocols stay errors everywhere.
			sev := Error
			if prof.MinVersion <= model.TLS10 && v >= model.TLS10 {
				sev = Warning
			}
			out = append(out, Finding{
				Rule: "CL001", Severity: sev, File: s.File, Line: s.Protocols.Line, Server: s.Name,
				Message:  fmt.Sprintf("%s is enabled%s; it is formally deprecated and every dated profile since 2021 forbids it", v, note),
				Citation: doc001.Citation,
			})
			continue
		}
		if v < prof.MinVersion {
			out = append(out, Finding{
				Rule: "CL002", Severity: Warning, File: s.File, Line: s.Protocols.Line, Server: s.Name,
				Message:  fmt.Sprintf("%s is enabled%s, but the %s profile floor is %s", v, note, prof.Name, prof.MinVersion),
				Citation: doc002.Citation,
			})
		}
	}
	if prof.RequireTLS13 && !s.HasVersion(model.TLS13) {
		doc := ruleByID["CL003"]
		out = append(out, Finding{
			Rule: "CL003", Severity: Warning, File: s.File, Line: s.Protocols.Line, Server: s.Name,
			Message:  fmt.Sprintf("TLS 1.3 is not among the enabled versions%s", note),
			Citation: doc.Citation,
		})
	}
	return out
}

// implicitNote explains where an assumed default comes from.
func implicitNote(s *model.Server) string {
	switch s.Format {
	case "apache":
		return " (SSLProtocol not set; httpd defaults to `all -SSLv3`, which includes TLS 1.0/1.1)"
	case "nginx":
		return " (ssl_protocols not set; assuming the nginx >= 1.23.4 default)"
	case "haproxy":
		return " (no ssl-min-ver; assuming the HAProxy >= 2.2 default)"
	case "caddy":
		return " (protocols not set; assuming Caddy defaults)"
	}
	return " (implicit default)"
}

func lintCipherList(s *model.Server, prof policy.Profile) []Finding {
	if !s.Ciphers.Set {
		return nil
	}
	line := s.Ciphers.Line
	var out []Finding
	emit := func(rule, severity, msg string) {
		doc := ruleByID[rule]
		out = append(out, Finding{
			Rule: rule, Severity: severity, File: s.File, Line: line, Server: s.Name,
			Message: msg, Citation: doc.Citation,
		})
	}

	var selected []ciphers.Suite
	var unknown, tls13Named []string
	if s.CipherDialect == model.DialectIANA {
		for _, name := range strings.Fields(s.Ciphers.Value) {
			suite, ok := ciphers.ByIANA(name)
			switch {
			case !ok:
				unknown = append(unknown, name)
			case suite.TLS13:
				tls13Named = append(tls13Named, name)
			default:
				selected = append(selected, suite)
			}
		}
	} else {
		exp := ciphers.Expand(s.Ciphers.Value)
		selected, unknown, tls13Named = exp.Suites, exp.Unknown, exp.TLS13
	}

	for _, tok := range unknown {
		emit("CL014", Info, fmt.Sprintf("cipher token %q is not a suite or keyword cipherlint knows; verify it is not a typo", tok))
	}
	for _, name := range tls13Named {
		emit("CL014", Info, fmt.Sprintf("%s is a TLS 1.3 suite; cipher lists cannot configure TLS 1.3 (it has no effect here)", name))
	}
	if len(selected) == 0 && len(unknown) == 0 && len(tls13Named) > 0 {
		emit("CL015", Error, "the cipher list selects zero TLS <= 1.2 suites while TLS <= 1.2 is enabled; pre-1.3 clients cannot connect")
		return out
	}
	if len(selected) == 0 {
		if len(unknown) == 0 {
			emit("CL015", Error, "the cipher list evaluates to zero suites while TLS <= 1.2 is enabled")
		}
		return out
	}

	group := func(pred func(ciphers.Suite) bool) []string {
		var names []string
		for _, c := range selected {
			if pred(c) {
				names = append(names, c.Name)
			}
		}
		return names
	}
	list := func(names []string) string {
		if len(names) > 5 {
			return strings.Join(names[:5], ", ") + fmt.Sprintf(", … (%d total)", len(names))
		}
		return strings.Join(names, ", ")
	}

	// CL004 — broken by design or cryptanalysis, one finding per category.
	if n := group(func(c ciphers.Suite) bool { return c.Enc == "NONE" }); len(n) > 0 {
		emit("CL004", Error, "NULL-encryption suites reachable (traffic would be plaintext): "+list(n))
	}
	if n := group(func(c ciphers.Suite) bool { return c.Au == "NONE" && c.Enc != "NONE" }); len(n) > 0 {
		emit("CL004", Error, "anonymous key-exchange suites reachable (trivial man-in-the-middle): "+list(n))
	}
	if n := group(ciphers.Suite.Export); len(n) > 0 {
		emit("CL004", Error, "export-grade suites reachable (FREAK-class downgrade): "+list(n))
	}
	if n := group(func(c ciphers.Suite) bool { return c.Enc == "DES" && !c.Export() }); len(n) > 0 {
		emit("CL004", Error, "single-DES suites reachable (56-bit keys fall to brute force): "+list(n))
	}
	if n := group(func(c ciphers.Suite) bool { return c.Enc == "RC4" && !c.Export() }); len(n) > 0 {
		emit("CL004", Error, "RC4 suites reachable; RFC 7465 prohibits RC4 in TLS: "+list(n))
	}
	if n := group(func(c ciphers.Suite) bool { return c.Enc == "3DES" }); len(n) > 0 {
		emit("CL004", Error, "3DES suites reachable (Sweet32 birthday attacks on 64-bit blocks): "+list(n))
	}

	// CL006 — static-RSA key exchange, no forward secrecy. Suites already
	// flagged as broken (RC4/DES/3DES/export/NULL) are not double-reported.
	if noFS := group(func(c ciphers.Suite) bool {
		return !c.ForwardSecrecy() && !c.Export() &&
			c.Enc != "NONE" && c.Enc != "RC4" && c.Enc != "DES" && c.Enc != "3DES"
	}); len(noFS) > 0 {
		sev := Info
		if prof.RequireFS {
			sev = Error
		}
		emit("CL006", sev, "static-RSA key exchange offers no forward secrecy: "+list(noFS))
	}

	// CL005 — CBC/HMAC survivors, only where the profile demands AEAD.
	if prof.RequireAEAD {
		if cbc := group(func(c ciphers.Suite) bool {
			return !c.AEAD() && c.Enc != "NONE" && c.Enc != "RC4" && c.Enc != "3DES" && c.Enc != "DES" && c.ForwardSecrecy() && c.Au != "NONE"
		}); len(cbc) > 0 {
			emit("CL005", Warning, fmt.Sprintf("non-AEAD (CBC+HMAC) suites reachable; the %s profile is AEAD-only: %s", prof.Name, list(cbc)))
		}
	}
	return out
}

// lintCiphersuites validates an explicit TLS 1.3 suite list (names only —
// every registered TLS 1.3 suite is sound).
func lintCiphersuites(s *model.Server) []Finding {
	if !s.Ciphersuites.Set {
		return nil
	}
	var out []Finding
	doc := ruleByID["CL014"]
	for _, name := range s.Ciphersuites.Value {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if suite, ok := ciphers.ByName(name); !ok || !suite.TLS13 {
			out = append(out, Finding{
				Rule: "CL014", Severity: Info, File: s.File, Line: s.Ciphersuites.Line, Server: s.Name,
				Message:  fmt.Sprintf("%q is not a TLS 1.3 suite name; the ciphersuites directive expects TLS_* names", name),
				Citation: doc.Citation,
			})
		}
	}
	return out
}

func lintCurves(s *model.Server, prof policy.Profile) []Finding {
	if !s.Curves.Set || s.Curves.Implicit {
		return nil
	}
	var out []Finding
	doc := ruleByID["CL010"]
	recommended := map[string]bool{}
	for _, c := range prof.Curves {
		recommended[policy.NormalizeCurve(c)] = true
	}
	var outside []string
	for _, raw := range s.Curves.Value {
		c := policy.NormalizeCurve(raw)
		if c == "" || c == "auto" {
			continue
		}
		if reason, weak := policy.WeakCurves[c]; weak {
			out = append(out, Finding{
				Rule: "CL010", Severity: Error, File: s.File, Line: s.Curves.Line, Server: s.Name,
				Message:  fmt.Sprintf("curve %s is enabled (%s)", raw, reason),
				Citation: doc.Citation,
			})
			continue
		}
		if len(recommended) > 0 && !recommended[c] {
			outside = append(outside, raw)
		}
	}
	if len(outside) > 0 {
		out = append(out, Finding{
			Rule: "CL010", Severity: Info, File: s.File, Line: s.Curves.Line, Server: s.Name,
			Message: fmt.Sprintf("curves outside the %s profile's recommended set (x25519, secp256r1, secp384r1): %s",
				prof.Name, strings.Join(outside, ", ")),
			Citation: doc.Citation,
		})
	}
	return out
}

func lintHSTS(s *model.Server, prof policy.Profile) []Finding {
	if prof.HSTSMinAge <= 0 {
		return nil
	}
	var out []Finding
	if !s.HSTS.Set {
		doc := ruleByID["CL011"]
		out = append(out, Finding{
			Rule: "CL011", Severity: Info, File: s.File, Line: s.Line, Server: s.Name,
			Message:  "no Strict-Transport-Security header configured; first visits stay downgradable",
			Citation: doc.Citation,
		})
		return out
	}
	if s.HSTS.Value.MaxAge < prof.HSTSMinAge {
		doc := ruleByID["CL012"]
		out = append(out, Finding{
			Rule: "CL012", Severity: Warning, File: s.File, Line: s.HSTS.Line, Server: s.Name,
			Message: fmt.Sprintf("HSTS max-age is %d; the %s profile recommends at least %d (two years)",
				s.HSTS.Value.MaxAge, prof.Name, prof.HSTSMinAge),
			Citation: doc.Citation,
		})
	}
	return out
}
