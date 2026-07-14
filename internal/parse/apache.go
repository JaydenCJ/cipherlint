// Apache httpd (mod_ssl) config parsing. Apache configs are line-oriented:
// directives are case-insensitive, arguments may be quoted, lines may
// continue with a trailing backslash, and <VirtualHost> containers scope
// per-vhost settings. Global mod_ssl directives are inherited by every
// vhost, matching httpd's own merge behavior.
package parse

import (
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

type apacheLine struct {
	name string   // lower-cased directive name
	args []string // original-case arguments
	line int
}

// apacheLines splits src into logical directive lines, honoring '#'
// comments, backslash continuations and quoted arguments.
func apacheLines(src string) []apacheLine {
	var out []apacheLine
	raw := strings.Split(src, "\n")
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		lineNo := i + 1
		for strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(raw) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + strings.TrimSpace(raw[i+1])
			i++
		}
		fields := splitQuoted(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, apacheLine{name: strings.ToLower(fields[0]), args: fields[1:], line: lineNo})
	}
	return out
}

// splitQuoted splits one config line into fields, respecting double quotes
// and dropping '#' comments (a '#' inside quotes is literal).
func splitQuoted(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			fields = append(fields, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == '#':
			flush()
			return fields
		case !inQuote && (c == ' ' || c == '\t' || c == '\r'):
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return fields
}

// Apache parses an httpd config and returns one model.Server per
// <VirtualHost> that enables SSL, or a file-scope server when SSL directives
// appear outside any vhost (the common ssl.conf layout).
func Apache(file, src string) []model.Server {
	lines := apacheLines(src)

	var global []apacheLine
	type vh struct {
		name string
		line int
		dirs []apacheLine
	}
	var vhosts []vh
	var cur *vh
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l.name, "<virtualhost"):
			name := "*"
			if len(l.args) > 0 {
				name = strings.TrimSuffix(l.args[0], ">")
			} else {
				name = strings.TrimSuffix(strings.TrimPrefix(l.name, "<virtualhost"), ">")
			}
			vhosts = append(vhosts, vh{name: name, line: l.line})
			cur = &vhosts[len(vhosts)-1]
		case l.name == "</virtualhost>":
			cur = nil
		case strings.HasPrefix(l.name, "<") && cur != nil:
			// Nested container inside a vhost (Directory, IfModule, ...):
			// keep its contents, they merge into the vhost for our purposes.
			cur.dirs = append(cur.dirs, l)
		case strings.HasPrefix(l.name, "</") && cur != nil:
			// Closing tag of a nested container: nothing to record.
		case cur != nil:
			cur.dirs = append(cur.dirs, l)
		case strings.HasPrefix(l.name, "<") || strings.HasPrefix(l.name, "</"):
			// global containers such as <IfModule ssl_module>: keep contents.
		default:
			global = append(global, l)
		}
	}

	var servers []model.Server
	if len(vhosts) == 0 {
		s := newApacheServer(file, "(file scope)", 0)
		if applyApacheDirectives(&s, global) {
			servers = append(servers, s)
		}
		return servers
	}
	for _, v := range vhosts {
		s := newApacheServer(file, v.name, v.line)
		applied := applyApacheDirectives(&s, global)
		sslOn := false
		for _, d := range v.dirs {
			if d.name == "sslengine" && len(d.args) > 0 && strings.EqualFold(d.args[0], "on") {
				sslOn = true
			}
			if d.name == "servername" && len(d.args) > 0 {
				s.Name = d.args[0]
			}
		}
		if applyApacheDirectives(&s, v.dirs) {
			applied = true
		}
		if sslOn || applied {
			servers = append(servers, s)
		}
	}
	return servers
}

// newApacheServer seeds documented httpd 2.4 defaults: SSLProtocol
// "all -SSLv3" (TLS 1.0-1.3 enabled!), SSLHonorCipherOrder off,
// SSLSessionTickets on, SSLUseStapling off.
func newApacheServer(file, name string, line int) model.Server {
	return model.Server{
		Format:        "apache",
		Name:          name,
		File:          file,
		Line:          line,
		CipherDialect: model.DialectOpenSSL,
		Protocols:     model.Default([]model.Version{model.TLS10, model.TLS11, model.TLS12, model.TLS13}),
		PreferServer:  model.Default(false),
		SessionTicket: model.Default(true),
		Stapling:      model.Default(false),
	}
}

func applyApacheDirectives(s *model.Server, dirs []apacheLine) bool {
	applied := false
	for _, d := range dirs {
		switch d.name {
		case "sslprotocol":
			s.Protocols = model.Explicit(apacheProtocolSet(d.args), d.line)
		case "sslciphersuite":
			// Two forms: `SSLCipherSuite <spec>` for TLS <= 1.2 and
			// `SSLCipherSuite TLSv1.3 <suites>` for the 1.3 list (httpd 2.4.36+).
			// Spaces are legal separators in OpenSSL cipher strings, so a
			// value split across continuation lines joins back with spaces.
			if len(d.args) >= 2 && strings.EqualFold(d.args[0], "TLSv1.3") {
				s.Ciphersuites = model.Explicit(strings.Split(d.args[1], ":"), d.line)
			} else if len(d.args) >= 2 && strings.EqualFold(d.args[0], "SSL") {
				s.Ciphers = model.Explicit(strings.Join(d.args[1:], " "), d.line)
			} else if len(d.args) >= 1 {
				s.Ciphers = model.Explicit(strings.Join(d.args, " "), d.line)
			}
		case "sslhonorcipherorder":
			s.PreferServer = model.Explicit(onOff(d.args), d.line)
		case "sslsessiontickets":
			s.SessionTicket = model.Explicit(onOff(d.args), d.line)
		case "sslusestapling":
			s.Stapling = model.Explicit(onOff(d.args), d.line)
		case "sslopensslconfcmd":
			if len(d.args) >= 2 && (strings.EqualFold(d.args[0], "Curves") || strings.EqualFold(d.args[0], "Groups")) {
				s.Curves = model.Explicit(strings.Split(d.args[1], ":"), d.line)
			} else {
				continue
			}
		case "header":
			// Header [always] set Strict-Transport-Security "max-age=..."
			args := d.args
			if len(args) > 0 && strings.EqualFold(args[0], "always") {
				args = args[1:]
			}
			if len(args) >= 3 && strings.EqualFold(args[0], "set") &&
				strings.EqualFold(args[1], "Strict-Transport-Security") {
				s.HSTS = model.Explicit(ParseHSTS(args[2]), d.line)
			} else {
				continue
			}
		default:
			continue
		}
		applied = true
	}
	return applied
}

// apacheProtocolSet evaluates SSLProtocol's additive syntax:
// `all -SSLv3 +TLSv1.2` — `all` enables everything, bare or `+` names add,
// `-` names remove.
func apacheProtocolSet(args []string) []model.Version {
	enabled := make(map[model.Version]bool)
	for _, a := range args {
		op := byte(0)
		if len(a) > 0 && (a[0] == '+' || a[0] == '-') {
			op, a = a[0], a[1:]
		}
		if strings.EqualFold(a, "all") {
			// httpd 2.4 "all" == +SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3
			for _, v := range []model.Version{model.SSLv3, model.TLS10, model.TLS11, model.TLS12, model.TLS13} {
				enabled[v] = op != '-'
			}
			continue
		}
		if v, ok := model.ParseVersion(a); ok {
			enabled[v] = op != '-'
		}
	}
	var out []model.Version
	for _, v := range model.AllVersions {
		if enabled[v] {
			out = append(out, v)
		}
	}
	return out
}
