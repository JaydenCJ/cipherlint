// HAProxy parser tests: the global-defaults-plus-bind-override merge is
// where real HAProxy misconfigurations hide, so every combination the docs
// allow gets a case.
package parse

import (
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

const haproxyGlobal = `
global
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets
    tune.ssl.default-dh-param 2048

frontend https
    bind :443 ssl crt /etc/haproxy/site.pem
`

func TestHAProxyGlobalDefaultsApplyToBind(t *testing.T) {
	servers := HAProxy("haproxy.cfg", haproxyGlobal)
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	s := servers[0]
	if s.Ciphers.Value != "ECDHE+AESGCM:ECDHE+CHACHA20" {
		t.Fatalf("global ciphers not inherited: %q", s.Ciphers.Value)
	}
	if len(s.Ciphersuites.Value) != 2 {
		t.Fatalf("ciphersuites: %v", s.Ciphersuites.Value)
	}
	if s.SessionTicket.Value {
		t.Fatal("no-tls-tickets should disable session tickets")
	}
	if s.HasVersion(model.TLS10) || s.HasVersion(model.TLS11) || !s.HasVersion(model.TLS12) {
		t.Fatalf("protocols wrong: %v", s.Protocols.Value)
	}
	if !s.DHBits.Set || s.DHBits.Value != 2048 {
		t.Fatalf("tune.ssl.default-dh-param not inherited: %+v", s.DHBits)
	}
}

func TestHAProxyBindOverridesGlobal(t *testing.T) {
	src := haproxyGlobal + `
frontend legacy
    bind :8443 ssl crt /etc/haproxy/legacy.pem ciphers HIGH ssl-min-ver TLSv1.2
`
	servers := HAProxy("haproxy.cfg", src)
	if len(servers) != 2 {
		t.Fatalf("got %d servers", len(servers))
	}
	legacy := servers[1]
	if legacy.Ciphers.Value != "HIGH" {
		t.Fatalf("bind-level ciphers should override: %q", legacy.Ciphers.Value)
	}
	if legacy.HasVersion(model.TLS11) || !legacy.HasVersion(model.TLS12) {
		t.Fatalf("ssl-min-ver override wrong: %v", legacy.Protocols.Value)
	}
}

func TestHAProxySSLMinVerRange(t *testing.T) {
	src := `
frontend f
    bind :443 ssl crt /x.pem ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2
`
	s := HAProxy("haproxy.cfg", src)[0]
	if !s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS12) || s.HasVersion(model.TLS13) {
		t.Fatalf("min/max range wrong: %v", s.Protocols.Value)
	}
	if s.Protocols.Implicit {
		t.Fatal("explicit ssl-min-ver must not be implicit")
	}
}

func TestHAProxyNoOptionsOnlyDisableNamed(t *testing.T) {
	// A config with only `no-sslv3` re-opens TLS 1.0/1.1 — the exact trap
	// the linter exists to catch, so the parser must model it faithfully.
	src := `
global
    ssl-default-bind-options no-sslv3

frontend f
    bind :443 ssl crt /x.pem
`
	s := HAProxy("haproxy.cfg", src)[0]
	if s.HasVersion(model.SSLv3) {
		t.Fatal("SSLv3 should be off")
	}
	if !s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS11) {
		t.Fatalf("no-sslv3 alone leaves TLS 1.0/1.1 enabled: %v", s.Protocols.Value)
	}
}

func TestHAProxyDefaultMinVersionImplicit(t *testing.T) {
	src := "frontend f\n    bind :443 ssl crt /x.pem\n"
	s := HAProxy("haproxy.cfg", src)[0]
	if !s.Protocols.Implicit {
		t.Fatal("defaulted protocols should be implicit")
	}
	if s.HasVersion(model.TLS11) || !s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) {
		t.Fatalf("HAProxy >= 2.2 default is TLS 1.2+: %v", s.Protocols.Value)
	}
}

func TestHAProxyHSTSAndNonSSLBindIgnored(t *testing.T) {
	src := `
frontend plain
    bind :80

frontend f
    bind :443 ssl crt /x.pem
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains"
`
	servers := HAProxy("haproxy.cfg", src)
	if len(servers) != 1 || servers[0].Name != "f :443" {
		t.Fatalf("only the ssl bind should be linted: %+v", servers)
	}
	s := servers[0]
	if !s.HSTS.Set || s.HSTS.Value.MaxAge != 63072000 || !s.HSTS.Value.IncludeSubDomains {
		t.Fatalf("HSTS: %+v", s.HSTS)
	}
}

func TestHAProxyPreferClientCiphers(t *testing.T) {
	src := `
global
    ssl-default-bind-options prefer-client-ciphers

frontend f
    bind :443 ssl crt /x.pem
`
	s := HAProxy("haproxy.cfg", src)[0]
	if s.PreferServer.Value || s.PreferServer.Implicit {
		t.Fatalf("prefer-client-ciphers should set PreferServer=false explicitly: %+v", s.PreferServer)
	}
	// And the default (no option) is server-preference on, implicitly.
	s2 := HAProxy("haproxy.cfg", "frontend f\n    bind :443 ssl crt /x.pem\n")[0]
	if !s2.PreferServer.Value || !s2.PreferServer.Implicit {
		t.Fatalf("default should be implicit server preference: %+v", s2.PreferServer)
	}
}
