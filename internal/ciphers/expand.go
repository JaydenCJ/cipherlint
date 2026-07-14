// OpenSSL cipher-string evaluation. nginx (ssl_ciphers), Apache
// (SSLCipherSuite) and HAProxy (ciphers / ssl-default-bind-ciphers) all pass
// their cipher directive to OpenSSL verbatim, so linting them honestly means
// evaluating the same mini-language: ordered keywords, `!` `-` `+` operators,
// `+`-joined intersections, and `@STRENGTH`. This file implements the subset
// documented in docs/cipher-strings.md against the offline Table.
package ciphers

import (
	"sort"
	"strings"
)

// Expansion is the result of evaluating a cipher string.
type Expansion struct {
	Suites  []Suite  // the ordered TLS <= 1.2 suite list the string selects
	Unknown []string // tokens cipherlint could not interpret
	TLS13   []string // TLS 1.3 suite names used in the string (they have no effect there)
}

// Names returns the OpenSSL names of the expanded suites, in order.
func (e Expansion) Names() []string {
	out := make([]string, len(e.Suites))
	for i, s := range e.Suites {
		out[i] = s.Name
	}
	return out
}

// Expand evaluates an OpenSSL cipher string. Semantics follow
// ciphers(1ssl): tokens are separated by ':', ',' or spaces and processed
// left to right; a bare token appends its matches; '!' deletes matches
// permanently; '-' deletes but allows later re-adding; '+' moves existing
// matches to the end; 'A+B' (infix) intersects; '@STRENGTH' sorts by
// symmetric key bits, strongest first. TLS 1.3 suites are excluded from the
// universe because OpenSSL ignores cipher strings for TLS 1.3.
func Expand(spec string) Expansion {
	var exp Expansion
	list := make([]Suite, 0, 32)
	killed := make(map[string]bool)

	inList := func(name string) int {
		for i, s := range list {
			if s.Name == name {
				return i
			}
		}
		return -1
	}

	for _, tok := range splitTokens(spec) {
		if tok == "@STRENGTH" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Bits > list[j].Bits })
			continue
		}
		op := byte(0)
		body := tok
		if len(tok) > 0 && (tok[0] == '!' || tok[0] == '-' || tok[0] == '+') {
			op, body = tok[0], tok[1:]
		}
		if body == "" {
			exp.Unknown = append(exp.Unknown, tok)
			continue
		}
		if _, isTLS13 := tls13ByName(body); isTLS13 {
			exp.TLS13 = append(exp.TLS13, body)
			continue
		}
		matches, ok := matchToken(body)
		if !ok {
			exp.Unknown = append(exp.Unknown, tok)
			continue
		}
		switch op {
		case 0: // append new matches, in table order
			for _, m := range matches {
				if !killed[m.Name] && inList(m.Name) < 0 {
					list = append(list, m)
				}
			}
		case '!': // kill: delete and bar from re-adding
			for _, m := range matches {
				killed[m.Name] = true
				if i := inList(m.Name); i >= 0 {
					list = append(list[:i], list[i+1:]...)
				}
			}
		case '-': // delete, but a later bare token may re-add
			for _, m := range matches {
				if i := inList(m.Name); i >= 0 {
					list = append(list[:i], list[i+1:]...)
				}
			}
		case '+': // move current matches to the end, preserving relative order
			var kept, moved []Suite
			matched := make(map[string]bool, len(matches))
			for _, m := range matches {
				matched[m.Name] = true
			}
			for _, s := range list {
				if matched[s.Name] {
					moved = append(moved, s)
				} else {
					kept = append(kept, s)
				}
			}
			list = append(kept, moved...)
		}
	}
	exp.Suites = list
	return exp
}

func splitTokens(spec string) []string {
	return strings.FieldsFunc(spec, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t'
	})
}

func tls13ByName(body string) (Suite, bool) {
	s, ok := ByName(body)
	if ok && s.TLS13 {
		return s, true
	}
	return Suite{}, false
}

// matchToken resolves one token body (no operator prefix) to suites from the
// TLS <= 1.2 universe, in table order. An infix '+' intersects parts:
// ECDHE+AESGCM matches suites that are both ECDHE and AES-GCM. Returns
// ok=false if any part is neither a keyword nor an exact suite name.
func matchToken(body string) ([]Suite, bool) {
	parts := strings.Split(body, "+")
	preds := make([]func(Suite) bool, 0, len(parts))
	for _, p := range parts {
		pred, ok := predicate(p)
		if !ok {
			return nil, false
		}
		preds = append(preds, pred)
	}
	var out []Suite
	for _, s := range Table {
		if s.TLS13 {
			continue
		}
		all := true
		for _, pred := range preds {
			if !pred(s) {
				all = false
				break
			}
		}
		if all {
			out = append(out, s)
		}
	}
	return out, true
}

// predicate maps one keyword (or exact suite name) to a suite predicate.
// Keyword set and grouping follow ciphers(1ssl); DEFAULT is approximated as
// ALL:!aNULL:!eNULL (documented in docs/cipher-strings.md).
func predicate(kw string) (func(Suite) bool, bool) {
	if s, ok := ByName(kw); ok && !s.TLS13 {
		name := s.Name
		return func(t Suite) bool { return t.Name == name }, true
	}
	switch kw {
	case "ALL": // everything except NULL encryption
		return func(s Suite) bool { return s.Enc != "NONE" }, true
	case "DEFAULT": // approximation: ALL:!aNULL:!eNULL
		return func(s Suite) bool { return s.Enc != "NONE" && s.Au != "NONE" }, true
	case "COMPLEMENTOFDEFAULT":
		return func(s Suite) bool { return s.Au == "NONE" && s.Enc != "NONE" }, true
	case "HIGH": // >= 128-bit modern ciphers (OpenSSL security-level view)
		return func(s Suite) bool {
			return s.Bits >= 128 && s.Enc != "RC4" && s.Enc != "SEED" && s.Enc != "NONE"
		}, true
	case "MEDIUM": // 128-bit legacy ciphers
		return func(s Suite) bool { return s.Bits == 128 && (s.Enc == "RC4" || s.Enc == "SEED") }, true
	case "LOW": // <= 64-bit (single DES); 3DES moved to its own keyword in 1.1.0
		return func(s Suite) bool { return s.Bits > 0 && s.Bits <= 64 && !s.Export() }, true
	case "EXPORT", "EXP":
		return func(s Suite) bool { return s.Export() }, true
	case "eNULL", "NULL":
		return func(s Suite) bool { return s.Enc == "NONE" }, true
	case "aNULL":
		return func(s Suite) bool { return s.Au == "NONE" }, true
	case "kRSA", "RSA": // ciphers(1ssl): RSA == RSA key exchange
		return func(s Suite) bool { return s.Kx == "RSA" }, true
	case "aRSA":
		return func(s Suite) bool { return s.Au == "RSA" }, true
	case "ECDSA", "aECDSA":
		return func(s Suite) bool { return s.Au == "ECDSA" }, true
	case "ECDHE", "EECDH", "kEECDH", "kECDHE":
		return func(s Suite) bool { return s.Kx == "ECDHE" }, true
	case "DHE", "EDH", "kEDH", "kDHE":
		return func(s Suite) bool { return s.Kx == "DHE" }, true
	case "AES":
		return func(s Suite) bool { return s.Enc == "AES" || s.Enc == "AESGCM" || s.Enc == "CCM" }, true
	case "AESGCM":
		return func(s Suite) bool { return s.Enc == "AESGCM" }, true
	case "AES128":
		return func(s Suite) bool { return (s.Enc == "AES" || s.Enc == "AESGCM" || s.Enc == "CCM") && s.Bits == 128 }, true
	case "AES256":
		return func(s Suite) bool { return (s.Enc == "AES" || s.Enc == "AESGCM") && s.Bits == 256 }, true
	case "CHACHA20":
		return func(s Suite) bool { return s.Enc == "CHACHA20" }, true
	case "CAMELLIA":
		return func(s Suite) bool { return s.Enc == "CAMELLIA" }, true
	case "SEED":
		return func(s Suite) bool { return s.Enc == "SEED" }, true
	case "3DES":
		return func(s Suite) bool { return s.Enc == "3DES" }, true
	case "DES":
		return func(s Suite) bool { return s.Enc == "DES" }, true
	case "RC4":
		return func(s Suite) bool { return s.Enc == "RC4" }, true
	case "MD5":
		return func(s Suite) bool { return s.MAC == "MD5" }, true
	case "SHA", "SHA1":
		return func(s Suite) bool { return s.MAC == "SHA1" }, true
	case "SHA256":
		return func(s Suite) bool { return s.MAC == "SHA256" }, true
	case "SHA384":
		return func(s Suite) bool { return s.MAC == "SHA384" }, true
	case "TLSv1.2": // suites that require TLS 1.2 (AEAD or SHA-2 MAC)
		return func(s Suite) bool { return s.MAC == "AEAD" || s.MAC == "SHA256" || s.MAC == "SHA384" }, true
	}
	return nil, false
}
