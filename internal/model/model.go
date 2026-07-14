// Package model defines the normalized TLS configuration that every parser
// (nginx, Caddy, Apache, HAProxy) produces and that the lint engine consumes.
// Parsers never judge; they only record what the config file says, where it
// says it, and whether a value is an explicit directive or a documented
// server default (Implicit).
package model

import "strings"

// Version enumerates SSL/TLS protocol versions in chronological order, so
// that ordinary integer comparison expresses "older than".
type Version int

const (
	SSLv2 Version = iota
	SSLv3
	TLS10
	TLS11
	TLS12
	TLS13
)

// AllVersions lists every version cipherlint knows about, oldest first.
var AllVersions = []Version{SSLv2, SSLv3, TLS10, TLS11, TLS12, TLS13}

func (v Version) String() string {
	switch v {
	case SSLv2:
		return "SSLv2"
	case SSLv3:
		return "SSLv3"
	case TLS10:
		return "TLS 1.0"
	case TLS11:
		return "TLS 1.1"
	case TLS12:
		return "TLS 1.2"
	case TLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

// ParseVersion normalizes the many spellings the four config dialects use:
// nginx "TLSv1.2", Apache "TLSv1.2", HAProxy "TLSv1.2"/"tlsv12", Caddy
// "tls1.2". Returns false for names it does not recognize.
func ParseVersion(s string) (Version, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sslv2", "ssl2", "sslv2.0":
		return SSLv2, true
	case "sslv3", "ssl3", "sslv3.0":
		return SSLv3, true
	case "tlsv1", "tlsv1.0", "tls1.0", "tls1", "tlsv10":
		return TLS10, true
	case "tlsv1.1", "tls1.1", "tlsv11":
		return TLS11, true
	case "tlsv1.2", "tls1.2", "tlsv12":
		return TLS12, true
	case "tlsv1.3", "tls1.3", "tlsv13":
		return TLS13, true
	}
	return 0, false
}

// Setting wraps a config value with provenance. Set distinguishes "the file
// says nothing" from a zero value; Implicit marks values synthesized from the
// server software's documented default rather than an explicit directive.
type Setting[T any] struct {
	Value    T
	Line     int
	Set      bool
	Implicit bool
}

// Explicit builds a Setting recorded from an actual directive at line.
func Explicit[T any](v T, line int) Setting[T] {
	return Setting[T]{Value: v, Line: line, Set: true}
}

// Default builds a Setting synthesized from a documented server default.
func Default[T any](v T) Setting[T] {
	return Setting[T]{Value: v, Set: true, Implicit: true}
}

// HSTS captures a parsed Strict-Transport-Security response header.
type HSTS struct {
	MaxAge            int64
	IncludeSubDomains bool
	Preload           bool
	Raw               string
}

// CipherDialect names the syntax a cipher list is written in.
type CipherDialect string

const (
	// DialectOpenSSL is the colon-separated OpenSSL cipher-string syntax
	// used by nginx, Apache and HAProxy (ECDHE-RSA-AES128-GCM-SHA256:...).
	DialectOpenSSL CipherDialect = "openssl"
	// DialectIANA is the standard suite-name syntax used by Caddy
	// (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ...).
	DialectIANA CipherDialect = "iana"
)

// Server is one TLS endpoint extracted from a config file: an nginx server
// block, an Apache VirtualHost, a HAProxy frontend/listen bind, or a Caddy
// site. Unset fields mean the directive is absent AND cipherlint has no
// documented default to assume for that server software.
type Server struct {
	Format string // "nginx" | "apache" | "haproxy" | "caddy"
	Name   string // server_name / vhost address / frontend name / site address
	File   string
	Line   int // line where the server context starts (0 for whole-file scope)

	Protocols     Setting[[]Version] // enabled protocol versions
	Ciphers       Setting[string]    // raw cipher list for TLS <= 1.2
	CipherDialect CipherDialect
	Ciphersuites  Setting[[]string] // TLS 1.3 suite names, if restricted
	PreferServer  Setting[bool]     // server-side cipher ordering
	SessionTicket Setting[bool]     // TLS session tickets
	Stapling      Setting[bool]     // OCSP stapling
	Curves        Setting[[]string] // ECDH curves / groups
	DHBits        Setting[int]      // ephemeral DH parameter size, when knowable
	HSTS          Setting[HSTS]     // Strict-Transport-Security header
}

// HasVersion reports whether the server's enabled protocol set includes v.
func (s *Server) HasVersion(v Version) bool {
	if !s.Protocols.Set {
		return false
	}
	for _, e := range s.Protocols.Value {
		if e == v {
			return true
		}
	}
	return false
}
