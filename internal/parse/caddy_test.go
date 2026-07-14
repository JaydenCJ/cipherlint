// Caddyfile parser tests: site blocks, the tls subdirective block, header
// forms, and the secure-by-default posture (implicit settings).
package parse

import (
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

func TestCaddySiteBlocks(t *testing.T) {
	src := `
a.example.test {
	tls {
		protocols tls1.2 tls1.3
	}
}

b.example.test {
	reverse_proxy 127.0.0.1:8080
}
`
	servers := Caddy("Caddyfile", src)
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
	if servers[0].Name != "a.example.test" || servers[1].Name != "b.example.test" {
		t.Fatalf("names: %q, %q", servers[0].Name, servers[1].Name)
	}
	if servers[0].Protocols.Implicit {
		t.Fatal("explicit protocols marked implicit")
	}
	if !servers[1].Protocols.Implicit {
		t.Fatal("site without tls block should carry implicit Caddy defaults")
	}
}

func TestCaddyProtocolsRange(t *testing.T) {
	src := "example.test {\n\ttls {\n\t\tprotocols tls1.0 tls1.2\n\t}\n}\n"
	s := Caddy("Caddyfile", src)[0]
	if !s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS11) || !s.HasVersion(model.TLS12) {
		t.Fatalf("range should enable 1.0-1.2: %v", s.Protocols.Value)
	}
	if s.HasVersion(model.TLS13) {
		t.Fatal("max tls1.2 should exclude TLS 1.3")
	}
	// One argument means "this version up to the default max (1.3)".
	s = Caddy("Caddyfile", "example.test {\n\ttls {\n\t\tprotocols tls1.3\n\t}\n}\n")[0]
	if s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) {
		t.Fatalf("protocols tls1.3 should be 1.3-only: %v", s.Protocols.Value)
	}
}

func TestCaddyCiphersAndCurves(t *testing.T) {
	src := `example.test {
	tls {
		ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		curves x25519 secp256r1
	}
}
`
	s := Caddy("Caddyfile", src)[0]
	if s.CipherDialect != model.DialectIANA {
		t.Fatalf("dialect: %s", s.CipherDialect)
	}
	if s.Ciphers.Value != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("ciphers: %q", s.Ciphers.Value)
	}
	if len(s.Curves.Value) != 2 || s.Curves.Value[0] != "x25519" {
		t.Fatalf("curves: %v", s.Curves.Value)
	}
}

func TestCaddyHeaderInlineAndBlock(t *testing.T) {
	inline := "example.test {\n\theader Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n}\n"
	s := Caddy("Caddyfile", inline)[0]
	if s.HSTS.Value.MaxAge != 31536000 {
		t.Fatalf("inline header: %+v", s.HSTS.Value)
	}
	block := "example.test {\n\theader {\n\t\tStrict-Transport-Security \"max-age=600\"\n\t}\n}\n"
	s2 := Caddy("Caddyfile", block)[0]
	if s2.HSTS.Value.MaxAge != 600 {
		t.Fatalf("block header: %+v", s2.HSTS.Value)
	}
}

func TestCaddyGlobalOptionsAndSingleSiteForm(t *testing.T) {
	// A leading anonymous block is Caddy's global options; it is not a site.
	src := "{\n\tadmin off\n}\n\nexample.test {\n\trespond \"ok\"\n}\n"
	servers := Caddy("Caddyfile", src)
	if len(servers) != 1 || servers[0].Name != "example.test" {
		t.Fatalf("global options block mishandled: %+v", servers)
	}
	// The minimal Caddyfile: address on line one, directives below, no braces.
	servers = Caddy("Caddyfile", "example.test\nrespond \"ok\"\n")
	if len(servers) != 1 || servers[0].Name != "example.test" {
		t.Fatalf("single-site form mishandled: %+v", servers)
	}
	if !servers[0].Protocols.Implicit || !servers[0].HasVersion(model.TLS13) {
		t.Fatalf("defaults: %+v", servers[0].Protocols)
	}
}
