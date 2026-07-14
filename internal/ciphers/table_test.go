// Tests for the suite metadata table itself: lookups, derived properties,
// and internal consistency (a wrong table row would silently produce wrong
// findings everywhere).
package ciphers

import (
	"strings"
	"testing"
)

func TestLookupsByOpenSSLAndIANAName(t *testing.T) {
	s, ok := ByName("ECDHE-ECDSA-AES128-GCM-SHA256")
	if !ok {
		t.Fatal("lookup failed")
	}
	if s.Kx != "ECDHE" || s.Au != "ECDSA" || s.Enc != "AESGCM" || s.Bits != 128 {
		t.Fatalf("wrong metadata: %+v", s)
	}
	if _, ok := ByName("ecdhe-ecdsa-aes128-gcm-sha256"); ok {
		t.Fatal("OpenSSL names are case-sensitive; lowercase must not match")
	}
	// Caddy accepts IANA suite names case-insensitively.
	s, ok = ByIANA("tls_ecdhe_rsa_with_aes_128_gcm_sha256")
	if !ok || s.Name != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Fatalf("IANA lookup failed: %+v ok=%v", s, ok)
	}
}

func TestSuiteDerivedFlags(t *testing.T) {
	cases := []struct {
		name           string
		aead, fs, expo bool
	}{
		{"ECDHE-RSA-AES128-GCM-SHA256", true, true, false},
		{"AES128-GCM-SHA256", true, false, false}, // AEAD but static RSA
		{"ECDHE-RSA-AES128-SHA", false, true, false},
		{"EXP-RC4-MD5", false, false, true},
	}
	for _, c := range cases {
		s, ok := ByName(c.name)
		if !ok {
			t.Fatalf("%s missing from table", c.name)
		}
		if s.AEAD() != c.aead || s.ForwardSecrecy() != c.fs || s.Export() != c.expo {
			t.Fatalf("%s: AEAD=%v FS=%v EXP=%v", c.name, s.AEAD(), s.ForwardSecrecy(), s.Export())
		}
	}
}

func TestTLS13Suites(t *testing.T) {
	suites := TLS13Suites()
	if len(suites) != 4 {
		t.Fatalf("expected 4 TLS 1.3 suites, got %d", len(suites))
	}
	for _, s := range suites {
		if !s.AEAD() || !s.ForwardSecrecy() {
			t.Fatalf("TLS 1.3 suite %s must be FS+AEAD", s.Name)
		}
	}
}

func TestTableInternalConsistency(t *testing.T) {
	seenName := map[string]bool{}
	seenIANA := map[string]bool{}
	for _, s := range Table {
		if seenName[s.Name] {
			t.Fatalf("duplicate OpenSSL name %s", s.Name)
		}
		if seenIANA[s.IANA] {
			t.Fatalf("duplicate IANA name %s", s.IANA)
		}
		seenName[s.Name], seenIANA[s.IANA] = true, true
		if !strings.HasPrefix(s.IANA, "TLS_") {
			t.Fatalf("%s: IANA name %q lacks TLS_ prefix", s.Name, s.IANA)
		}
		if (s.MAC == "AEAD") != s.AEAD() {
			t.Fatalf("%s: AEAD flag inconsistent", s.Name)
		}
		if s.Enc == "NONE" && s.Bits != 0 {
			t.Fatalf("%s: NULL cipher with nonzero bits", s.Name)
		}
		if s.Enc != "NONE" && s.Bits == 0 {
			t.Fatalf("%s: real cipher with zero bits", s.Name)
		}
	}
}
