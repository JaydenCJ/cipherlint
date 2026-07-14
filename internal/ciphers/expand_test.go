// Tests for the OpenSSL cipher-string evaluator. Every case mirrors a shape
// that really appears in production configs (Mozilla generator output,
// distro defaults, hand-rolled legacy strings), because the linter's honesty
// depends on expanding those exactly like OpenSSL does.
package ciphers

import (
	"reflect"
	"testing"
)

func names(t *testing.T, spec string) []string {
	t.Helper()
	return Expand(spec).Names()
}

func TestExpandOrderDedupAndSeparators(t *testing.T) {
	// The operator's order is the negotiation preference; expansion must
	// not silently reorder it.
	got := names(t, "AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256")
	want := []string{"AES256-SHA", "ECDHE-RSA-AES128-GCM-SHA256"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// OpenSSL accepts ':', ',' and spaces interchangeably.
	if b := names(t, "AES256-SHA, ECDHE-RSA-AES128-GCM-SHA256"); !reflect.DeepEqual(b, want) {
		t.Fatalf("comma separator differs: %v", b)
	}
	if c := names(t, "AES256-SHA ECDHE-RSA-AES128-GCM-SHA256"); !reflect.DeepEqual(c, want) {
		t.Fatalf("space separator differs: %v", c)
	}
	// A suite already selected is not re-added by a later keyword.
	got = names(t, "RC4-SHA:RC4-SHA:RC4")
	if got[0] != "RC4-SHA" {
		t.Fatalf("first suite = %s, want RC4-SHA", got[0])
	}
	seen := map[string]int{}
	for _, n := range got {
		seen[n]++
		if seen[n] > 1 {
			t.Fatalf("suite %s appears twice in %v", n, got)
		}
	}
}

func TestExpandBangKillsPermanently(t *testing.T) {
	// `!RC4` must bar RC4 suites even when a later token re-selects them —
	// this is the semantic operators rely on when appending !MD5 etc.
	got := names(t, "!RC4:ALL")
	for _, n := range got {
		if n == "RC4-SHA" || n == "RC4-MD5" {
			t.Fatalf("!RC4 failed to bar %s", n)
		}
	}
	if len(got) == 0 {
		t.Fatal("ALL after !RC4 should still select non-RC4 suites")
	}
}

func TestExpandMinusAllowsReAdd(t *testing.T) {
	// Unlike '!', '-' only deletes from the current list; a later token may
	// re-add.
	got := names(t, "ALL:-RC4:RC4-SHA")
	found := false
	for _, n := range got {
		if n == "RC4-SHA" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RC4-SHA should be re-addable after -RC4, got %v", got)
	}
}

func TestExpandPlusMovesToEnd(t *testing.T) {
	// `+SHA1` demotes SHA-1 suites without removing them (classic trick to
	// keep legacy clients working at lowest preference).
	got := names(t, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:+SHA1")
	want := []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExpandInfixIntersection(t *testing.T) {
	// ECDHE+AESGCM (the HAProxy-guide idiom) selects only suites that are
	// both ECDHE and AES-GCM.
	for _, n := range names(t, "ECDHE+AESGCM") {
		s, _ := ByName(n)
		if s.Kx != "ECDHE" || s.Enc != "AESGCM" {
			t.Fatalf("%s is not ECDHE+AESGCM", n)
		}
	}
	if len(names(t, "ECDHE+AESGCM")) == 0 {
		t.Fatal("ECDHE+AESGCM should match suites")
	}
}

func TestExpandStrengthSortsByBits(t *testing.T) {
	got := Expand("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:@STRENGTH")
	if got.Suites[0].Bits < got.Suites[1].Bits {
		t.Fatalf("@STRENGTH should sort strongest first, got %v", got.Names())
	}
}

func TestExpandHighExcludesRC4AndSeed(t *testing.T) {
	for _, n := range names(t, "HIGH") {
		s, _ := ByName(n)
		if s.Enc == "RC4" || s.Enc == "SEED" || s.Bits < 128 {
			t.Fatalf("HIGH selected %s (enc=%s bits=%d)", n, s.Enc, s.Bits)
		}
	}
}

func TestExpandDefaultAndANull(t *testing.T) {
	// DEFAULT ~= ALL:!aNULL:!eNULL — no anonymous or NULL suites.
	for _, n := range names(t, "DEFAULT") {
		s, _ := ByName(n)
		if s.Enc == "NONE" || s.Au == "NONE" {
			t.Fatalf("DEFAULT selected %s", n)
		}
	}
	got := names(t, "aNULL")
	if len(got) == 0 {
		t.Fatal("aNULL should match anonymous suites")
	}
	for _, n := range got {
		s, _ := ByName(n)
		if s.Au != "NONE" {
			t.Fatalf("aNULL selected authenticated suite %s", n)
		}
	}
}

func TestExpandKRSAKeyword(t *testing.T) {
	// ciphers(1ssl): both RSA and kRSA mean "RSA key exchange".
	if !reflect.DeepEqual(names(t, "kRSA"), names(t, "RSA")) {
		t.Fatal("kRSA and RSA must select the same suites")
	}
	for _, n := range names(t, "kRSA") {
		s, _ := ByName(n)
		if s.Kx != "RSA" {
			t.Fatalf("kRSA selected %s with kx=%s", n, s.Kx)
		}
	}
}

func TestExpandReportsUnknownAndTLS13Tokens(t *testing.T) {
	// Typos are recorded (OpenSSL would silently ignore them); TLS 1.3
	// names are recorded separately because cipher strings cannot configure
	// TLS 1.3 — the linter says so.
	exp := Expand("ECDHE-RSA-AES128-GCM-SHA256:TOTALLY-BOGUS:TLS_AES_128_GCM_SHA256")
	if len(exp.Unknown) != 1 || exp.Unknown[0] != "TOTALLY-BOGUS" {
		t.Fatalf("unknown = %v, want [TOTALLY-BOGUS]", exp.Unknown)
	}
	if len(exp.TLS13) != 1 || exp.TLS13[0] != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("TLS13 = %v", exp.TLS13)
	}
	if len(exp.Suites) != 1 || exp.Suites[0].Name != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Fatalf("known part of the string should still expand, got %v", exp.Names())
	}
}

func TestExpandEmptyResult(t *testing.T) {
	exp := Expand("HIGH:!HIGH")
	if len(exp.Suites) != 0 {
		t.Fatalf("HIGH:!HIGH should select nothing, got %v", exp.Names())
	}
}

func TestExpandMozillaIntermediateString(t *testing.T) {
	// The exact ssl_ciphers value Mozilla's generator emits for the
	// intermediate profile must expand to only forward-secret AEAD suites.
	spec := "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
		"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
		"DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:" +
		"DHE-RSA-CHACHA20-POLY1305"
	exp := Expand(spec)
	if len(exp.Unknown) != 0 {
		t.Fatalf("unknown tokens in Mozilla string: %v", exp.Unknown)
	}
	if len(exp.Suites) != 9 {
		t.Fatalf("expected 9 suites, got %d: %v", len(exp.Suites), exp.Names())
	}
	for _, s := range exp.Suites {
		if !s.AEAD() || !s.ForwardSecrecy() {
			t.Fatalf("%s is not FS+AEAD", s.Name)
		}
	}
}
