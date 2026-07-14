// Package ciphers holds cipherlint's offline cipher-suite knowledge: a
// metadata table for the suites that realistically appear in server configs,
// plus an evaluator for the OpenSSL cipher-string mini-language that nginx,
// Apache and HAProxy all share. Everything here is pure data and pure
// functions — no OpenSSL linkage, no network.
package ciphers

import "strings"

// Suite describes one cipher suite. Kx/Au/Enc/MAC follow OpenSSL's
// decomposition (`openssl ciphers -v`): key exchange, authentication,
// symmetric cipher, and MAC/PRF hash.
type Suite struct {
	Name  string // OpenSSL name (as written in nginx/Apache/HAProxy configs)
	IANA  string // IANA / RFC name (as written in Caddy configs)
	Kx    string // ECDHE, DHE, RSA, ECDH, ANY (TLS 1.3), NONE
	Au    string // RSA, ECDSA, NONE (anonymous), ANY (TLS 1.3)
	Enc   string // AESGCM, AES, CHACHA20, CCM, 3DES, DES, RC4, SEED, CAMELLIA, NONE
	Bits  int    // effective symmetric strength (3DES counted as 112)
	MAC   string // AEAD, SHA1, SHA256, SHA384, MD5
	TLS13 bool   // TLS 1.3-only suite (not configurable via cipher strings)
}

// AEAD reports whether the suite provides authenticated encryption.
func (s Suite) AEAD() bool { return s.MAC == "AEAD" }

// ForwardSecrecy reports whether the key exchange is ephemeral.
func (s Suite) ForwardSecrecy() bool {
	return s.Kx == "ECDHE" || s.Kx == "DHE" || s.Kx == "ANY"
}

// Export reports whether the suite is an export-grade (<= 512-bit RSA /
// 40-bit symmetric) relic.
func (s Suite) Export() bool { return strings.HasPrefix(s.Name, "EXP-") }

// suite is a compact constructor used by the table below.
func suite(name, iana, kx, au, enc string, bits int, mac string) Suite {
	return Suite{Name: name, IANA: iana, Kx: kx, Au: au, Enc: enc, Bits: bits, MAC: mac}
}

// Table lists every suite cipherlint recognizes, strongest-first within each
// family. Order matters: keyword expansion (ALL, HIGH, ECDHE+AESGCM, ...)
// yields suites in table order, mirroring how operators read `openssl
// ciphers` output. TLS 1.3 suites come first and are flagged: OpenSSL-style
// cipher strings cannot select them, so Expand skips them (see expand.go).
var Table = []Suite{
	// --- TLS 1.3 (RFC 8446) — configured separately, never via cipher strings.
	{Name: "TLS_AES_256_GCM_SHA384", IANA: "TLS_AES_256_GCM_SHA384", Kx: "ANY", Au: "ANY", Enc: "AESGCM", Bits: 256, MAC: "AEAD", TLS13: true},
	{Name: "TLS_CHACHA20_POLY1305_SHA256", IANA: "TLS_CHACHA20_POLY1305_SHA256", Kx: "ANY", Au: "ANY", Enc: "CHACHA20", Bits: 256, MAC: "AEAD", TLS13: true},
	{Name: "TLS_AES_128_GCM_SHA256", IANA: "TLS_AES_128_GCM_SHA256", Kx: "ANY", Au: "ANY", Enc: "AESGCM", Bits: 128, MAC: "AEAD", TLS13: true},
	{Name: "TLS_AES_128_CCM_SHA256", IANA: "TLS_AES_128_CCM_SHA256", Kx: "ANY", Au: "ANY", Enc: "CCM", Bits: 128, MAC: "AEAD", TLS13: true},

	// --- ECDHE + AEAD: the modern TLS 1.2 core.
	suite("ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AESGCM", 256, "AEAD"),
	suite("ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AESGCM", 256, "AEAD"),
	suite("ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "CHACHA20", 256, "AEAD"),
	suite("ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "CHACHA20", 256, "AEAD"),
	suite("ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AESGCM", 128, "AEAD"),
	suite("ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AESGCM", 128, "AEAD"),
	suite("ECDHE-ECDSA-AES128-CCM", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "ECDHE", "ECDSA", "CCM", 128, "AEAD"),

	// --- DHE + AEAD.
	suite("DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AESGCM", 256, "AEAD"),
	suite("DHE-RSA-CHACHA20-POLY1305", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "RSA", "CHACHA20", 256, "AEAD"),
	suite("DHE-RSA-AES128-GCM-SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AESGCM", 128, "AEAD"),

	// --- Forward-secret CBC: legacy-compat, not AEAD.
	suite("ECDHE-ECDSA-AES256-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "AES", 256, "SHA384"),
	suite("ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES", 256, "SHA384"),
	suite("ECDHE-ECDSA-AES128-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "AES", 128, "SHA256"),
	suite("ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES", 128, "SHA256"),
	suite("ECDHE-ECDSA-AES256-SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "AES", 256, "SHA1"),
	suite("ECDHE-RSA-AES256-SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "AES", 256, "SHA1"),
	suite("ECDHE-ECDSA-AES128-SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "AES", 128, "SHA1"),
	suite("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES", 128, "SHA1"),
	suite("DHE-RSA-AES256-SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "AES", 256, "SHA256"),
	suite("DHE-RSA-AES128-SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "AES", 128, "SHA256"),
	suite("DHE-RSA-AES256-SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES", 256, "SHA1"),
	suite("DHE-RSA-AES128-SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES", 128, "SHA1"),
	suite("DHE-RSA-CAMELLIA256-SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE", "RSA", "CAMELLIA", 256, "SHA1"),
	suite("DHE-RSA-CAMELLIA128-SHA", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "DHE", "RSA", "CAMELLIA", 128, "SHA1"),

	// --- Static RSA key exchange: no forward secrecy.
	suite("AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AESGCM", 256, "AEAD"),
	suite("AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AESGCM", 128, "AEAD"),
	suite("AES256-SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "AES", 256, "SHA256"),
	suite("AES128-SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "AES", 128, "SHA256"),
	suite("AES256-SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES", 256, "SHA1"),
	suite("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", 128, "SHA1"),
	suite("CAMELLIA256-SHA", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "RSA", "RSA", "CAMELLIA", 256, "SHA1"),
	suite("CAMELLIA128-SHA", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "RSA", "RSA", "CAMELLIA", 128, "SHA1"),
	suite("SEED-SHA", "TLS_RSA_WITH_SEED_CBC_SHA", "RSA", "RSA", "SEED", 128, "SHA1"),

	// --- Broken by design or by cryptanalysis. Kept so lint can name them.
	suite("ECDHE-RSA-DES-CBC3-SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "RSA", "3DES", 112, "SHA1"),
	suite("EDH-RSA-DES-CBC3-SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", "3DES", 112, "SHA1"),
	suite("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", 112, "SHA1"),
	suite("ECDHE-RSA-RC4-SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RSA", "RC4", 128, "SHA1"),
	suite("ECDHE-ECDSA-RC4-SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "ECDSA", "RC4", 128, "SHA1"),
	suite("RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", 128, "SHA1"),
	suite("RC4-MD5", "TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", "RC4", 128, "MD5"),
	suite("DES-CBC-SHA", "TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES", 56, "SHA1"),
	suite("EXP-DES-CBC-SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", "RSA", "DES", 40, "SHA1"),
	suite("EXP-RC4-MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", "RC4", 40, "MD5"),
	suite("NULL-SHA256", "TLS_RSA_WITH_NULL_SHA256", "RSA", "RSA", "NONE", 0, "SHA256"),
	suite("NULL-SHA", "TLS_RSA_WITH_NULL_SHA", "RSA", "RSA", "NONE", 0, "SHA1"),
	suite("NULL-MD5", "TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NONE", 0, "MD5"),
	suite("ADH-AES256-GCM-SHA384", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "DHE", "NONE", "AESGCM", 256, "AEAD"),
	suite("ADH-AES128-SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "DHE", "NONE", "AES", 128, "SHA1"),
	suite("AECDH-AES128-SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDHE", "NONE", "AES", 128, "SHA1"),
	suite("AECDH-NULL-SHA", "TLS_ECDH_anon_WITH_NULL_SHA", "ECDHE", "NONE", "NONE", 0, "SHA1"),
}

var (
	byName map[string]int
	byIANA map[string]int
)

func init() {
	byName = make(map[string]int, len(Table))
	byIANA = make(map[string]int, len(Table))
	for i, s := range Table {
		byName[s.Name] = i
		byIANA[s.IANA] = i
	}
}

// ByName looks a suite up by its OpenSSL name (exact, case-sensitive — the
// dialect OpenSSL itself uses).
func ByName(name string) (Suite, bool) {
	i, ok := byName[name]
	if !ok {
		return Suite{}, false
	}
	return Table[i], true
}

// ByIANA looks a suite up by its IANA/RFC name; Caddy accepts these
// case-insensitively, so we do too.
func ByIANA(name string) (Suite, bool) {
	i, ok := byIANA[strings.ToUpper(name)]
	if !ok {
		return Suite{}, false
	}
	return Table[i], true
}

// TLS13Suites returns the TLS 1.3 suites in preference order.
func TLS13Suites() []Suite {
	var out []Suite
	for _, s := range Table {
		if s.TLS13 {
			out = append(out, s)
		}
	}
	return out
}
