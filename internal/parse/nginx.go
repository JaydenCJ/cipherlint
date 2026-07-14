// nginx config parsing. cipherlint reads the real directive grammar
// (`name arg arg;` plus `{}` blocks, comments, quoting) rather than
// regexing lines, walks http -> server contexts with inheritance, and
// normalizes the ssl_* directives into model.Server values. Snippet files
// with bare ssl_* directives (conf.d includes) are handled by synthesizing a
// single file-scope server.
package parse

import (
	"strconv"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

// directive is one parsed statement: a name, its arguments, the line it
// starts on, and (for block directives) its children.
type directive struct {
	name  string
	args  []string
	line  int
	block []directive
}

// lexNginx tokenizes nginx-style syntax: '#' comments, single/double quotes,
// and the structural tokens '{', '}', ';'.
func lexNginx(src string) []token {
	return lex(src, lexOpts{comment: "#", semi: true})
}

type token struct {
	text string
	line int
	kind byte // 'w' word, '{', '}', ';', 'n' newline (caddy mode only)
}

type lexOpts struct {
	comment  string
	semi     bool // ';' terminates directives (nginx)
	newlines bool // emit newline tokens (caddy)
}

func lex(src string, o lexOpts) []token {
	var toks []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			if o.newlines {
				toks = append(toks, token{kind: 'n', line: line})
			}
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case o.comment != "" && c == o.comment[0]:
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '{' || c == '}' || (o.semi && c == ';'):
			toks = append(toks, token{text: string(c), line: line, kind: c})
			i++
		case c == '"' || c == '\'':
			quote := c
			i++
			start := i
			var sb strings.Builder
			for i < len(src) && src[i] != quote {
				if src[i] == '\\' && i+1 < len(src) {
					sb.WriteString(src[start:i])
					i++
					start = i
				}
				if src[i] == '\n' {
					line++
				}
				i++
			}
			sb.WriteString(src[start:i])
			if i < len(src) {
				i++ // closing quote
			}
			toks = append(toks, token{text: sb.String(), line: line, kind: 'w'})
		default:
			start := i
			for i < len(src) {
				c := src[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '{' || c == '}' || (o.semi && c == ';') {
					break
				}
				if o.comment != "" && c == o.comment[0] {
					break
				}
				i++
			}
			toks = append(toks, token{text: src[start:i], line: line, kind: 'w'})
		}
	}
	return toks
}

// parseNginxDirectives builds the directive tree from tokens.
func parseNginxDirectives(toks []token) []directive {
	dirs, _ := parseNginxBlock(toks, 0)
	return dirs
}

func parseNginxBlock(toks []token, i int) ([]directive, int) {
	var out []directive
	for i < len(toks) {
		t := toks[i]
		if t.kind == '}' {
			return out, i + 1
		}
		if t.kind == ';' {
			i++
			continue
		}
		d := directive{name: t.text, line: t.line}
		i++
		for i < len(toks) && toks[i].kind == 'w' {
			d.args = append(d.args, toks[i].text)
			i++
		}
		if i < len(toks) && toks[i].kind == '{' {
			d.block, i = parseNginxBlock(toks, i+1)
		} else if i < len(toks) && toks[i].kind == ';' {
			i++
		}
		out = append(out, d)
	}
	return out, i
}

// Nginx parses an nginx configuration and returns one model.Server per
// server block that terminates TLS (has `listen ... ssl` or any ssl_*
// directive, directly or inherited).
func Nginx(file, src string) []model.Server {
	tree := parseNginxDirectives(lexNginx(src))

	// Flatten: collect (inheritedDirectives, serverBlock) pairs. ssl_*
	// directives at main or http level are inherited by every server.
	var servers []model.Server
	var inherited []directive
	var serverBlocks []directive

	var walk func(dirs []directive, topLevel bool)
	walk = func(dirs []directive, topLevel bool) {
		for _, d := range dirs {
			switch d.name {
			case "http":
				walk(d.block, true)
			case "server":
				if topLevel {
					serverBlocks = append(serverBlocks, d)
				}
			default:
				if topLevel && d.block == nil {
					inherited = append(inherited, d)
				}
			}
		}
	}
	walk(tree, true)

	if len(serverBlocks) == 0 {
		// Snippet file: bare ssl_* directives with no server context.
		s := newNginxServer(file, "(file scope)", 0)
		applied := applyNginxDirectives(&s, inherited)
		if applied {
			servers = append(servers, s)
		}
		return servers
	}

	for _, sb := range serverBlocks {
		name := "server"
		tls := false
		for _, d := range sb.block {
			if d.name == "server_name" && len(d.args) > 0 {
				name = d.args[0]
			}
			if d.name == "listen" {
				for _, a := range d.args {
					if a == "ssl" {
						tls = true
					}
				}
			}
		}
		s := newNginxServer(file, name, sb.line)
		applied := applyNginxDirectives(&s, inherited)
		if applyNginxDirectives(&s, sb.block) {
			applied = true
		}
		if tls || applied {
			servers = append(servers, s)
		}
	}
	return servers
}

// newNginxServer seeds documented nginx defaults (nginx >= 1.23.4 with
// OpenSSL >= 1.1.1): ssl_protocols "TLSv1.2 TLSv1.3", session tickets on,
// server preference off, stapling off.
func newNginxServer(file, name string, line int) model.Server {
	return model.Server{
		Format:        "nginx",
		Name:          name,
		File:          file,
		Line:          line,
		CipherDialect: model.DialectOpenSSL,
		Protocols:     model.Default([]model.Version{model.TLS12, model.TLS13}),
		SessionTicket: model.Default(true),
		PreferServer:  model.Default(false),
		Stapling:      model.Default(false),
	}
}

// applyNginxDirectives copies recognized directives onto s and reports
// whether any TLS-relevant directive was present.
func applyNginxDirectives(s *model.Server, dirs []directive) bool {
	applied := false
	for _, d := range dirs {
		switch d.name {
		case "ssl_protocols":
			var vs []model.Version
			for _, a := range d.args {
				if v, ok := model.ParseVersion(a); ok {
					vs = append(vs, v)
				}
			}
			s.Protocols = model.Explicit(vs, d.line)
		case "ssl_ciphers":
			if len(d.args) > 0 {
				s.Ciphers = model.Explicit(d.args[0], d.line)
			}
		case "ssl_conf_command":
			// ssl_conf_command Ciphersuites TLS_...:TLS_... configures the
			// TLS 1.3 suite list when nginx is built against OpenSSL >= 1.1.1.
			if len(d.args) == 2 && strings.EqualFold(d.args[0], "Ciphersuites") {
				s.Ciphersuites = model.Explicit(strings.Split(d.args[1], ":"), d.line)
			}
		case "ssl_prefer_server_ciphers":
			s.PreferServer = model.Explicit(onOff(d.args), d.line)
		case "ssl_session_tickets":
			s.SessionTicket = model.Explicit(onOff(d.args), d.line)
		case "ssl_stapling":
			s.Stapling = model.Explicit(onOff(d.args), d.line)
		case "ssl_ecdh_curve":
			if len(d.args) > 0 {
				s.Curves = model.Explicit(strings.Split(d.args[0], ":"), d.line)
			}
		case "add_header":
			if len(d.args) >= 2 && strings.EqualFold(d.args[0], "Strict-Transport-Security") {
				s.HSTS = model.Explicit(ParseHSTS(d.args[1]), d.line)
			}
		default:
			continue
		}
		applied = true
	}
	return applied
}

func onOff(args []string) bool {
	return len(args) > 0 && strings.EqualFold(args[0], "on")
}

// ParseHSTS parses a Strict-Transport-Security header value.
func ParseHSTS(v string) model.HSTS {
	h := model.HSTS{Raw: v}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "max-age="):
			if n, err := strconv.ParseInt(strings.Trim(part[len("max-age="):], `"`), 10, 64); err == nil {
				h.MaxAge = n
			}
		case lower == "includesubdomains":
			h.IncludeSubDomains = true
		case lower == "preload":
			h.Preload = true
		}
	}
	return h
}
