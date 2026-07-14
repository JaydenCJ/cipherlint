// Rule catalog: every finding cipherlint can emit, with the citation that
// backs it. `cipherlint explain CL004` prints these. Keeping the catalog as
// data (not strings scattered through the engine) guarantees the docs, the
// explain subcommand and the findings can never drift apart.
package lint

// Severity of a finding. Errors are weaknesses an attacker can use today;
// warnings are profile violations; infos are recommendations.
const (
	Error   = "error"
	Warning = "warning"
	Info    = "info"
)

// severityRank orders severities for --fail-on comparisons.
func severityRank(s string) int {
	switch s {
	case Error:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// RuleDoc documents one rule for `cipherlint explain` and docs/rules.md.
type RuleDoc struct {
	ID       string
	Title    string
	Summary  string
	Citation string
}

// Rules is the complete catalog, ordered by ID.
var Rules = []RuleDoc{
	{
		ID:    "CL001",
		Title: "obsolete protocol enabled",
		Summary: "SSLv2, SSLv3, TLS 1.0 or TLS 1.1 is enabled. SSLv2 and SSLv3 are " +
			"prohibited outright; TLS 1.0/1.1 were formally deprecated in 2021 and " +
			"every dated profile since then forbids them (the `old` profile downgrades " +
			"this to a warning for documented legacy-client fleets).",
		Citation: "RFC 8996 (2021-03); RFC 7568 (SSLv3, 2015-06); RFC 6176 (SSLv2, 2011-03)",
	},
	{
		ID:       "CL002",
		Title:    "protocol below profile floor",
		Summary:  "A protocol version older than the selected profile's minimum is enabled — e.g. TLS 1.2 under the `modern` profile, which is TLS 1.3-only.",
		Citation: "profile table (see `cipherlint profiles`)",
	},
	{
		ID:       "CL003",
		Title:    "TLS 1.3 not enabled",
		Summary:  "The enabled protocol set does not include TLS 1.3. Every dated profile since 2019 expects TLS 1.3 to be on; leaving it off costs 1-RTT handshakes and the strongest available suites.",
		Citation: "RFC 8446 (2018-08); profile table",
	},
	{
		ID:       "CL004",
		Title:    "broken cipher suite reachable",
		Summary:  "The cipher list selects suites that are broken by design or by published cryptanalysis: NULL/anonymous suites, export grades, single DES, RC4, or 3DES.",
		Citation: "RFC 7465 (RC4, 2015-02); Sweet32 CVE-2016-2183 (3DES, 2016-08); FREAK CVE-2015-0204 (export, 2015-03)",
	},
	{
		ID:       "CL005",
		Title:    "legacy CBC/HMAC cipher suite",
		Summary:  "The cipher list selects non-AEAD (CBC + HMAC) suites. The modern and intermediate profiles are AEAD-only; CBC suites survive only in the `old` profile for legacy clients.",
		Citation: "Lucky Thirteen (2013-02); profile table",
	},
	{
		ID:       "CL006",
		Title:    "no forward secrecy",
		Summary:  "The cipher list selects static-RSA key-exchange suites. Without (EC)DHE, one leaked private key retroactively decrypts every recorded session.",
		Citation: "RFC 9325 §4.1 (2022-11); profile table",
	},
	{
		ID:       "CL007",
		Title:    "cipher-order preference against profile",
		Summary:  "Server-side cipher ordering is explicitly set against the profile's advice. Since all acceptable suites are strong, modern guidance lets the client pick (it knows whether it has AES hardware); the `old` profile still wants the server to win.",
		Citation: "profile table (Mozilla flipped this recommendation in v5, 2020-09)",
	},
	{
		ID:       "CL008",
		Title:    "session tickets enabled",
		Summary:  "TLS session tickets are explicitly enabled. Pre-TLS-1.3 tickets encrypted with a long-lived, unrotated key silently defeat forward secrecy across all resumed sessions.",
		Citation: "profile table; RFC 9325 §4.3.3 (2022-11)",
	},
	{
		ID:       "CL009",
		Title:    "weak DH parameters",
		Summary:  "The configured ephemeral Diffie-Hellman parameter size is below the profile minimum. 1024-bit groups are within reach of well-funded attackers (Logjam); 2048 bits is the floor.",
		Citation: "Logjam CVE-2015-4000 (2015-05); RFC 9325 §4.4",
	},
	{
		ID:       "CL010",
		Title:    "weak or non-recommended curve",
		Summary:  "An enabled ECDH curve is below the 112-bit security floor (error), or outside the profile's recommended set (info).",
		Citation: "NIST SP 800-57 Part 1 Rev. 5 (2020-05); profile table",
	},
	{
		ID:       "CL011",
		Title:    "HSTS not configured",
		Summary:  "No Strict-Transport-Security header is set for this server. Without HSTS, first visits and expired caches can be downgraded to plaintext by an active attacker.",
		Citation: "RFC 6797 (2012-11); profile table",
	},
	{
		ID:       "CL012",
		Title:    "HSTS max-age too short",
		Summary:  "The Strict-Transport-Security max-age is below the profile recommendation (two years). Short max-age values reopen the downgrade window after brief outages.",
		Citation: "RFC 6797 §6.1.1; profile table",
	},
	{
		ID:       "CL013",
		Title:    "OCSP stapling against dated advice",
		Summary:  "OCSP stapling disagrees with the selected table vintage. Tables up to 2024 recommend stapling ON; the 2026 tables mark it RETIRED — major CAs ended OCSP service in 2025 in favor of short-lived certificates and CRLs, so stapling directives are now dead weight.",
		Citation: "2023 tables: Mozilla v5.7; 2026 tables: Let's Encrypt ended OCSP support (2025-08)",
	},
	{
		ID:       "CL014",
		Title:    "unintelligible cipher token",
		Summary:  "A token in the cipher list is not a known suite or keyword (often a typo, which OpenSSL silently ignores — the directive may match nothing you intended), or is a TLS 1.3 suite name, which cipher strings cannot configure.",
		Citation: "ciphers(1ssl); docs/cipher-strings.md",
	},
	{
		ID:       "CL015",
		Title:    "cipher list selects nothing",
		Summary:  "After evaluation the cipher list contains zero TLS <= 1.2 suites. With TLS <= 1.2 enabled, the server cannot complete a handshake with pre-1.3 clients at all.",
		Citation: "ciphers(1ssl)",
	},
}

// ruleByID indexes Rules for explain and for attaching citations.
var ruleByID = func() map[string]RuleDoc {
	m := make(map[string]RuleDoc, len(Rules))
	for _, r := range Rules {
		m[r.ID] = r
	}
	return m
}()

// Doc returns the catalog entry for a rule ID.
func Doc(id string) (RuleDoc, bool) {
	r, ok := ruleByID[id]
	return r, ok
}
