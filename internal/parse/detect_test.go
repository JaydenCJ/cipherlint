// Auto-detection tests: filename conventions first, then content scoring.
package parse

import "testing"

func TestDetectByFilename(t *testing.T) {
	cases := map[string]string{
		"/etc/caddy/Caddyfile":       "caddy",
		"/etc/haproxy/haproxy.cfg":   "haproxy",
		"/etc/nginx/nginx.conf":      "nginx",
		"/etc/httpd/conf/httpd.conf": "apache",
		"apache2.conf":               "apache",
	}
	for file, want := range cases {
		if got := Detect(file, ""); got != want {
			t.Fatalf("Detect(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestDetectByContent(t *testing.T) {
	cases := []struct {
		want, src string
	}{
		{"nginx", "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1.2;\n    ssl_ciphers HIGH;\n}\n"},
		{"apache", "<VirtualHost *:443>\nSSLEngine on\nSSLProtocol all -SSLv3\n</VirtualHost>\n"},
		{"haproxy", "global\n    ssl-default-bind-ciphers HIGH\n\nfrontend https\n    bind :443 ssl crt /x.pem\n"},
		{"caddy", "example.test {\n\ttls {\n\t\tprotocols tls1.2 tls1.3\n\t}\n\treverse_proxy 127.0.0.1:8080\n}\n"},
	}
	for _, c := range cases {
		if got := Detect("site.conf", c.src); got != c.want {
			t.Fatalf("Detect = %q, want %q for:\n%s", got, c.want, c.src)
		}
	}
}

func TestDetectUnknownReturnsEmpty(t *testing.T) {
	if got := Detect("notes.txt", "just some text\n"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
