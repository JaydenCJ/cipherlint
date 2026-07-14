// Caddyfile parsing. Caddy is TLS-secure by default, so cipherlint focuses
// on what operators override: the `tls` directive's `protocols`, `ciphers`
// and `curves` subdirectives, plus `header Strict-Transport-Security`.
// Caddyfile syntax is newline-terminated directives with `{}` blocks and no
// semicolons; the top-of-file `{ ... }` block holds global options.
package parse

import (
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

// caddyNode mirrors directive from nginx.go but for newline-terminated syntax.
type caddyNode struct {
	name  string
	args  []string
	line  int
	block []caddyNode
}

func parseCaddyNodes(toks []token, i int) ([]caddyNode, int) {
	var out []caddyNode
	for i < len(toks) {
		t := toks[i]
		switch t.kind {
		case 'n':
			i++
		case '}':
			return out, i + 1
		case '{':
			// Anonymous block at line start (the global options block).
			var block []caddyNode
			block, i = parseCaddyNodes(toks, i+1)
			out = append(out, caddyNode{name: "{}", line: t.line, block: block})
		default:
			n := caddyNode{name: t.text, line: t.line}
			i++
			for i < len(toks) && toks[i].kind == 'w' {
				n.args = append(n.args, toks[i].text)
				i++
			}
			if i < len(toks) && toks[i].kind == '{' {
				n.block, i = parseCaddyNodes(toks, i+1)
			}
			out = append(out, n)
		}
	}
	return out, i
}

// Caddy parses a Caddyfile and returns one model.Server per site block (or a
// file-scope server for a single-site Caddyfile without an address block).
func Caddy(file, src string) []model.Server {
	toks := lex(src, lexOpts{comment: "#", newlines: true})
	nodes, _ := parseCaddyNodes(toks, 0)

	var servers []model.Server
	sawSite := false
	for _, n := range nodes {
		if n.name == "{}" {
			continue // global options: servers/admin/etc. — no TLS policy we lint
		}
		if n.block != nil {
			// A site block: `example.test { ... }` or `example.test, other {`.
			sawSite = true
			s := newCaddyServer(file, strings.TrimSuffix(n.name, ","), n.line)
			applyCaddyDirectives(&s, n.block)
			servers = append(servers, s)
		}
	}
	if !sawSite {
		// Single-site Caddyfile: first line is the address, directives follow
		// at top level.
		name := "(file scope)"
		var rest []caddyNode
		for i, n := range nodes {
			if i == 0 && n.block == nil && n.name != "{}" && len(n.args) == 0 && looksLikeAddress(n.name) {
				name = n.name
				continue
			}
			rest = append(rest, n)
		}
		s := newCaddyServer(file, name, 0)
		if applyCaddyDirectives(&s, rest) || name != "(file scope)" {
			servers = append(servers, s)
		}
	}
	return servers
}

func looksLikeAddress(s string) bool {
	return strings.Contains(s, ".") || strings.Contains(s, ":") || strings.Contains(s, "localhost")
}

// newCaddyServer seeds Caddy defaults: TLS 1.2-1.3, a curated
// forward-secret AEAD cipher list, X25519 + NIST curves, no cipher-order
// override, no session-ticket or stapling knobs exposed.
func newCaddyServer(file, name string, line int) model.Server {
	return model.Server{
		Format:        "caddy",
		Name:          name,
		File:          file,
		Line:          line,
		CipherDialect: model.DialectIANA,
		Protocols:     model.Default([]model.Version{model.TLS12, model.TLS13}),
	}
}

func applyCaddyDirectives(s *model.Server, nodes []caddyNode) bool {
	applied := false
	for _, n := range nodes {
		switch n.name {
		case "tls":
			for _, sub := range n.block {
				switch sub.name {
				case "protocols":
					// protocols <min> [<max>]
					if len(sub.args) >= 1 {
						min, okMin := model.ParseVersion(sub.args[0])
						max := model.TLS13
						if len(sub.args) >= 2 {
							if v, ok := model.ParseVersion(sub.args[1]); ok {
								max = v
							}
						}
						if okMin {
							var vs []model.Version
							for _, v := range model.AllVersions {
								if v >= min && v <= max {
									vs = append(vs, v)
								}
							}
							s.Protocols = model.Explicit(vs, sub.line)
							applied = true
						}
					}
				case "ciphers":
					// Caddy: TLS 1.2 suite names; TLS 1.3 suites are fixed.
					s.Ciphers = model.Explicit(strings.Join(sub.args, " "), sub.line)
					applied = true
				case "curves":
					s.Curves = model.Explicit(sub.args, sub.line)
					applied = true
				}
			}
		case "header":
			// `header Strict-Transport-Security "..."` or a header block.
			if len(n.args) >= 2 && strings.EqualFold(n.args[0], "Strict-Transport-Security") {
				s.HSTS = model.Explicit(ParseHSTS(strings.Join(n.args[1:], " ")), n.line)
				applied = true
			}
			for _, sub := range n.block {
				if strings.EqualFold(sub.name, "Strict-Transport-Security") && len(sub.args) >= 1 {
					s.HSTS = model.Explicit(ParseHSTS(strings.Join(sub.args, " ")), sub.line)
					applied = true
				}
			}
		}
	}
	return applied
}
