// nginx parser tests. Inputs replicate real-world layouts: monolithic
// nginx.conf files, conf.d snippets, http-level defaults with per-server
// overrides, quoted directive arguments, and comments.
package parse

import (
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

func TestNginxServerBlockExtraction(t *testing.T) {
	src := `
http {
    server {
        listen 443 ssl;
        server_name a.example.test;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256';
    }
}`
	servers := Nginx("nginx.conf", src)
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	s := servers[0]
	if s.Name != "a.example.test" || s.Format != "nginx" {
		t.Fatalf("server identity wrong: %+v", s)
	}
	if !s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) || s.HasVersion(model.TLS11) {
		t.Fatalf("protocols wrong: %v", s.Protocols.Value)
	}
	if s.Ciphers.Value != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Fatalf("ciphers wrong: %q", s.Ciphers.Value)
	}
	if s.Protocols.Implicit {
		t.Fatal("explicit ssl_protocols must not be marked implicit")
	}
}

func TestNginxHTTPLevelInheritance(t *testing.T) {
	// ssl_* at http level applies to every server, like nginx itself.
	src := `
http {
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    server { listen 443 ssl; server_name a.example.test; }
    server { listen 443 ssl; server_name b.example.test; }
}`
	servers := Nginx("nginx.conf", src)
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
	for _, s := range servers {
		if s.SessionTicket.Value || s.SessionTicket.Implicit {
			t.Fatalf("%s: session tickets should be explicitly off", s.Name)
		}
	}
	if servers[0].Name != "a.example.test" || servers[1].Name != "b.example.test" {
		t.Fatalf("server names wrong: %q, %q", servers[0].Name, servers[1].Name)
	}
	if servers[0].Line == servers[1].Line {
		t.Fatal("distinct server blocks must keep distinct line numbers")
	}
}

func TestNginxServerOverridesHTTP(t *testing.T) {
	src := `
http {
    ssl_protocols TLSv1 TLSv1.1;
    server {
        listen 443 ssl;
        ssl_protocols TLSv1.3;
    }
}`
	servers := Nginx("nginx.conf", src)
	if len(servers) != 1 {
		t.Fatalf("got %d servers", len(servers))
	}
	s := servers[0]
	if s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS13) {
		t.Fatalf("server-level ssl_protocols must override http-level: %v", s.Protocols.Value)
	}
}

func TestNginxCommentsAndQuotes(t *testing.T) {
	src := `
server {
    listen 443 ssl; # comment with ssl_protocols TLSv1 inside
    ssl_ciphers "HIGH:!aNULL"; # quoted
    ssl_protocols TLSv1.2; # trailing
}`
	servers := Nginx("nginx.conf", src)
	if len(servers) != 1 {
		t.Fatalf("got %d servers", len(servers))
	}
	s := servers[0]
	if s.Ciphers.Value != "HIGH:!aNULL" {
		t.Fatalf("quoted ciphers wrong: %q", s.Ciphers.Value)
	}
	if s.HasVersion(model.TLS10) {
		t.Fatal("commented-out protocol leaked into the parse")
	}
}

func TestNginxSnippetWithoutServerBlock(t *testing.T) {
	// conf.d/ssl.conf style: bare directives, no server context.
	src := "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;\n"
	servers := Nginx("ssl.conf", src)
	if len(servers) != 1 {
		t.Fatalf("snippet should synthesize one file-scope server, got %d", len(servers))
	}
	if servers[0].Name != "(file scope)" {
		t.Fatalf("name = %q", servers[0].Name)
	}
}

func TestNginxImplicitDefaults(t *testing.T) {
	// With no ssl_protocols, cipherlint assumes the modern nginx default
	// (TLS 1.2 + 1.3) and marks it implicit so lint messages can say so.
	src := `server { listen 443 ssl; ssl_ciphers HIGH; }`
	s := Nginx("nginx.conf", src)[0]
	if !s.Protocols.Implicit {
		t.Fatal("protocols should be implicit")
	}
	if !s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) || s.HasVersion(model.TLS11) {
		t.Fatalf("implicit default wrong: %v", s.Protocols.Value)
	}
	if !s.SessionTicket.Value || !s.SessionTicket.Implicit {
		t.Fatal("session tickets default on (implicit)")
	}
}

func TestNginxHSTSCurvesAndCiphersuites(t *testing.T) {
	src := `
server {
    listen 443 ssl;
    ssl_ecdh_curve X25519:prime256v1;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}`
	s := Nginx("nginx.conf", src)[0]
	if len(s.Curves.Value) != 2 || s.Curves.Value[0] != "X25519" {
		t.Fatalf("curves wrong: %v", s.Curves.Value)
	}
	if !s.Ciphersuites.Set || len(s.Ciphersuites.Value) != 2 {
		t.Fatalf("ssl_conf_command Ciphersuites: %+v", s.Ciphersuites)
	}
	h := s.HSTS.Value
	if h.MaxAge != 63072000 || !h.IncludeSubDomains || !h.Preload {
		t.Fatalf("HSTS parse wrong: %+v", h)
	}
}

func TestParseHSTSValueForms(t *testing.T) {
	cases := []struct {
		in     string
		maxAge int64
		sub    bool
	}{
		{"max-age=31536000", 31536000, false},
		{"max-age=63072000; includeSubDomains", 63072000, true},
		{`max-age="600"`, 600, false}, // quoted number, seen in the wild
		{"includeSubDomains", 0, true},
	}
	for _, c := range cases {
		h := ParseHSTS(c.in)
		if h.MaxAge != c.maxAge || h.IncludeSubDomains != c.sub {
			t.Fatalf("%q: got %+v", c.in, h)
		}
	}
}
