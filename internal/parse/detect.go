// Format auto-detection. cipherlint prefers explicit --server flags, then
// filename conventions, then content scoring: each dialect has unmistakable
// signature strings, and the dialect with the most matches wins. Scoring is
// deterministic; ties go to the order nginx > apache > haproxy > caddy and a
// zero score means "unknown".
package parse

import (
	"path/filepath"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

// Formats lists the supported --server values.
var Formats = []string{"nginx", "apache", "haproxy", "caddy"}

// Parse dispatches to the parser for format. Format must be one of Formats.
func Parse(format, file, src string) []model.Server {
	switch format {
	case "nginx":
		return Nginx(file, src)
	case "apache":
		return Apache(file, src)
	case "haproxy":
		return HAProxy(file, src)
	case "caddy":
		return Caddy(file, src)
	}
	return nil
}

// Detect guesses the config dialect of file from its name and contents.
// Returns "" when nothing matches.
func Detect(file, src string) string {
	base := strings.ToLower(filepath.Base(file))
	switch {
	case strings.HasPrefix(base, "caddyfile"):
		return "caddy"
	case strings.Contains(base, "haproxy"):
		return "haproxy"
	case strings.Contains(base, "nginx"):
		return "nginx"
	case strings.Contains(base, "httpd") || strings.Contains(base, "apache"):
		return "apache"
	}

	scores := map[string]int{}
	count := func(format string, needles ...string) {
		for _, n := range needles {
			scores[format] += strings.Count(src, n)
		}
	}
	count("nginx", "ssl_protocols", "ssl_ciphers", "server_name", "ssl_prefer_server_ciphers", "listen ")
	count("apache", "<VirtualHost", "SSLEngine", "SSLProtocol", "SSLCipherSuite", "SSLHonorCipherOrder")
	count("haproxy", "ssl-default-bind", "tune.ssl", "\nfrontend ", "\nbackend ", "ssl-min-ver", "\nbind ")
	if strings.HasPrefix(src, "frontend ") || strings.HasPrefix(src, "global") {
		scores["haproxy"] += 2
	}
	count("caddy", "\ntls {", "\n\ttls {", "reverse_proxy", "file_server", "encode gzip")

	best, bestScore := "", 0
	for _, f := range Formats {
		if scores[f] > bestScore {
			best, bestScore = f, scores[f]
		}
	}
	return best
}
