// Apache parser tests, covering the httpd-specific hazards: additive
// SSLProtocol syntax, the dangerous `all -SSLv3` default, global-to-vhost
// inheritance, case-insensitive directives and line continuations.
package parse

import (
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

func TestApacheVirtualHostExtraction(t *testing.T) {
	src := `
<VirtualHost *:443>
    ServerName www.example.test
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256
</VirtualHost>`
	servers := Apache("httpd.conf", src)
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	s := servers[0]
	if s.Name != "www.example.test" || s.Format != "apache" {
		t.Fatalf("identity wrong: %+v", s)
	}
	if s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) {
		t.Fatalf("protocols wrong: %v", s.Protocols.Value)
	}
	// httpd directives are case-insensitive.
	lower := Apache("httpd.conf", "<virtualhost *:443>\nsslengine ON\nsslprotocol -ALL +tlsv1.3\n</virtualhost>\n")
	if len(lower) != 1 || !lower[0].HasVersion(model.TLS13) {
		t.Fatalf("case-insensitive parse failed: %+v", lower)
	}
}

func TestApacheProtocolAdditiveSyntax(t *testing.T) {
	// `all -SSLv3 -TLSv1 -TLSv1.1` is the classic hardening line.
	src := `
<VirtualHost *:443>
    SSLEngine on
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
</VirtualHost>`
	s := Apache("httpd.conf", src)[0]
	for _, v := range []model.Version{model.SSLv3, model.TLS10, model.TLS11} {
		if s.HasVersion(v) {
			t.Fatalf("%s should be disabled", v)
		}
	}
	if !s.HasVersion(model.TLS12) || !s.HasVersion(model.TLS13) {
		t.Fatalf("TLS 1.2/1.3 should remain: %v", s.Protocols.Value)
	}
}

func TestApacheDefaultProtocolIncludesLegacy(t *testing.T) {
	// httpd's compiled-in default is `all -SSLv3`: TLS 1.0 and 1.1 are ON.
	// The parser must surface that as an implicit setting so lint can flag it.
	src := `
<VirtualHost *:443>
    SSLEngine on
    SSLCipherSuite HIGH
</VirtualHost>`
	s := Apache("httpd.conf", src)[0]
	if !s.Protocols.Implicit {
		t.Fatal("unset SSLProtocol should be implicit")
	}
	if !s.HasVersion(model.TLS10) || !s.HasVersion(model.TLS11) {
		t.Fatalf("httpd default enables TLS 1.0/1.1, got %v", s.Protocols.Value)
	}
}

func TestApacheGlobalInheritance(t *testing.T) {
	src := `
SSLProtocol -all +TLSv1.3
SSLSessionTickets off
<VirtualHost *:443>
    SSLEngine on
    ServerName a.example.test
</VirtualHost>`
	s := Apache("httpd.conf", src)[0]
	if !s.HasVersion(model.TLS13) || s.HasVersion(model.TLS12) {
		t.Fatalf("global SSLProtocol not inherited: %v", s.Protocols.Value)
	}
	if s.SessionTicket.Value {
		t.Fatal("global SSLSessionTickets off not inherited")
	}
}

func TestApacheTLS13CipherSuiteForm(t *testing.T) {
	// httpd 2.4.36+: `SSLCipherSuite TLSv1.3 <suites>` sets the 1.3 list
	// without touching the TLS <= 1.2 list.
	src := `
<VirtualHost *:443>
    SSLEngine on
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
    SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256
</VirtualHost>`
	s := Apache("httpd.conf", src)[0]
	if len(s.Ciphersuites.Value) != 2 {
		t.Fatalf("ciphersuites: %v", s.Ciphersuites.Value)
	}
	if s.Ciphers.Value != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Fatalf("ciphers: %q", s.Ciphers.Value)
	}
}

func TestApacheLineContinuation(t *testing.T) {
	// Backslash continuations join into one directive; the parts become a
	// space-joined cipher string (spaces are legal OpenSSL separators).
	src := "<VirtualHost *:443>\nSSLEngine on\nSSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:\\\n    ECDHE-RSA-AES256-GCM-SHA384\n</VirtualHost>\n"
	s := Apache("httpd.conf", src)[0]
	want := "ECDHE-RSA-AES128-GCM-SHA256: ECDHE-RSA-AES256-GCM-SHA384"
	if s.Ciphers.Value != want {
		t.Fatalf("continuation join wrong: %q", s.Ciphers.Value)
	}
}

func TestApacheHSTSHeaderAndCurves(t *testing.T) {
	src := `
<VirtualHost *:443>
    SSLEngine on
    SSLOpenSSLConfCmd Curves X25519:secp384r1
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>`
	s := Apache("httpd.conf", src)[0]
	if len(s.Curves.Value) != 2 {
		t.Fatalf("curves: %v", s.Curves.Value)
	}
	if s.HSTS.Value.MaxAge != 63072000 {
		t.Fatalf("HSTS: %+v", s.HSTS.Value)
	}
}

func TestApacheFileScopeConfig(t *testing.T) {
	// A bare ssl.conf with no vhost still gets linted at file scope.
	src := "SSLProtocol all -SSLv3\nSSLCipherSuite HIGH:!aNULL\n"
	servers := Apache("ssl.conf", src)
	if len(servers) != 1 || servers[0].Name != "(file scope)" {
		t.Fatalf("file-scope handling wrong: %+v", servers)
	}
}
