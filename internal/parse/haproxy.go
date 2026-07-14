// HAProxy config parsing. HAProxy splits TLS policy between the `global`
// section (ssl-default-bind-* directives, tune.ssl.default-dh-param) and the
// `ssl` keyword arguments of each `bind` line in frontend/listen sections.
// cipherlint merges the two exactly like HAProxy does: bind-level settings
// override the global defaults.
package parse

import (
	"strconv"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

// haproxyDefaults carries the global-section state that bind lines inherit.
type haproxyDefaults struct {
	minVer     model.Setting[model.Version]
	maxVer     model.Setting[model.Version]
	noVersions map[model.Version]int // version -> line of the no-* option
	ciphers    model.Setting[string]
	suites     model.Setting[[]string]
	noTickets  model.Setting[bool]
	preferSrv  model.Setting[bool] // prefer-client-ciphers inverts this
	curves     model.Setting[[]string]
	dhBits     model.Setting[int]
}

// HAProxy parses a haproxy.cfg and returns one model.Server per TLS-enabled
// bind line in frontend/listen sections.
func HAProxy(file, src string) []model.Server {
	def := haproxyDefaults{noVersions: map[model.Version]int{}}
	var servers []model.Server

	section := ""
	sectionName := ""
	sectionStart := 0
	var hstsLine *model.Setting[model.HSTS]
	flushHSTS := func() {
		if hstsLine != nil {
			for i := sectionStart; i < len(servers); i++ {
				if !servers[i].HSTS.Set {
					servers[i].HSTS = *hstsLine
				}
			}
		}
		hstsLine = nil
		sectionStart = len(servers)
	}

	for i, raw := range strings.Split(src, "\n") {
		lineNo := i + 1
		fields := splitQuoted(raw)
		if len(fields) == 0 {
			continue
		}
		head := strings.ToLower(fields[0])
		switch head {
		case "global", "defaults", "frontend", "listen", "backend", "resolvers", "peers":
			flushHSTS()
			section = head
			sectionName = head
			if len(fields) > 1 {
				sectionName = fields[1]
			}
			continue
		}

		switch section {
		case "global":
			parseHAProxyGlobal(&def, head, fields[1:], lineNo)
		case "frontend", "listen":
			if head == "bind" {
				if s, ok := parseHAProxyBind(file, sectionName, def, fields[1:], lineNo); ok {
					servers = append(servers, s)
				}
			}
			// http-response set-header Strict-Transport-Security "max-age=..."
			if head == "http-response" && len(fields) >= 4 &&
				strings.EqualFold(fields[1], "set-header") &&
				strings.EqualFold(fields[2], "Strict-Transport-Security") {
				h := model.Explicit(ParseHSTS(strings.Join(fields[3:], " ")), lineNo)
				hstsLine = &h
			}
		}
	}
	flushHSTS()
	return servers
}

func parseHAProxyGlobal(def *haproxyDefaults, head string, args []string, line int) {
	switch head {
	case "ssl-default-bind-ciphers":
		if len(args) > 0 {
			def.ciphers = model.Explicit(args[0], line)
		}
	case "ssl-default-bind-ciphersuites":
		if len(args) > 0 {
			def.suites = model.Explicit(strings.Split(args[0], ":"), line)
		}
	case "ssl-default-bind-curves":
		if len(args) > 0 {
			def.curves = model.Explicit(strings.Split(args[0], ":"), line)
		}
	case "ssl-default-bind-options":
		parseHAProxyOptions(def, args, line)
	case "tune.ssl.default-dh-param":
		if len(args) > 0 {
			if n, err := strconv.Atoi(args[0]); err == nil {
				def.dhBits = model.Explicit(n, line)
			}
		}
	}
}

func parseHAProxyOptions(def *haproxyDefaults, args []string, line int) {
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(args[i])
		switch a {
		case "no-sslv3":
			def.noVersions[model.SSLv3] = line
		case "no-tlsv10":
			def.noVersions[model.TLS10] = line
		case "no-tlsv11":
			def.noVersions[model.TLS11] = line
		case "no-tlsv12":
			def.noVersions[model.TLS12] = line
		case "no-tlsv13":
			def.noVersions[model.TLS13] = line
		case "no-tls-tickets":
			def.noTickets = model.Explicit(true, line)
		case "prefer-client-ciphers":
			def.preferSrv = model.Explicit(false, line)
		case "ssl-min-ver", "ssl-max-ver":
			if i+1 < len(args) {
				if v, ok := model.ParseVersion(args[i+1]); ok {
					if a == "ssl-min-ver" {
						def.minVer = model.Explicit(v, line)
					} else {
						def.maxVer = model.Explicit(v, line)
					}
				}
				i++
			}
		}
	}
}

// parseHAProxyBind evaluates one bind line. Returns ok=false when the bind
// does not terminate TLS (no `ssl` keyword).
func parseHAProxyBind(file, name string, def haproxyDefaults, args []string, line int) (model.Server, bool) {
	local := def
	local.noVersions = make(map[model.Version]int, len(def.noVersions))
	for k, v := range def.noVersions {
		local.noVersions[k] = v
	}
	ssl := false
	addr := ""
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(args[i])
		switch a {
		case "ssl":
			ssl = true
		case "ciphers":
			if i+1 < len(args) {
				local.ciphers = model.Explicit(args[i+1], line)
				i++
			}
		case "ciphersuites":
			if i+1 < len(args) {
				local.suites = model.Explicit(strings.Split(args[i+1], ":"), line)
				i++
			}
		case "curves":
			if i+1 < len(args) {
				local.curves = model.Explicit(strings.Split(args[i+1], ":"), line)
				i++
			}
		case "crt", "ca-file", "alpn", "npn", "verify":
			i++ // keyword with one value we don't need
		case "no-sslv3", "no-tlsv10", "no-tlsv11", "no-tlsv12", "no-tlsv13",
			"no-tls-tickets", "prefer-client-ciphers":
			parseHAProxyOptions(&local, []string{a}, line)
		case "ssl-min-ver", "ssl-max-ver":
			if i+1 < len(args) {
				parseHAProxyOptions(&local, []string{a, args[i+1]}, line)
				i++
			}
		default:
			if addr == "" && !strings.HasPrefix(a, "no-") {
				addr = args[i]
			}
		}
	}
	if !ssl {
		return model.Server{}, false
	}

	s := model.Server{
		Format:        "haproxy",
		Name:          name,
		File:          file,
		Line:          line,
		CipherDialect: model.DialectOpenSSL,
	}
	if addr != "" {
		s.Name = name + " " + addr
	}

	// Protocol set: HAProxy >= 2.2 defaults to ssl-min-ver TLSv1.2 when
	// neither ssl-min-ver nor no-* options say otherwise.
	minVer := model.Setting[model.Version]{}
	switch {
	case local.minVer.Set:
		minVer = local.minVer
	case len(local.noVersions) > 0:
		minVer = model.Explicit(model.SSLv3, local.lowestNoLine())
	default:
		minVer = model.Default(model.TLS12)
	}
	maxVer := model.TLS13
	if local.maxVer.Set {
		maxVer = local.maxVer.Value
	}
	var enabled []model.Version
	for _, v := range model.AllVersions {
		if v == model.SSLv2 {
			continue // OpenSSL cannot negotiate SSLv2 anymore
		}
		if v < minVer.Value || v > maxVer {
			continue
		}
		if _, off := local.noVersions[v]; off {
			continue
		}
		enabled = append(enabled, v)
	}
	s.Protocols = model.Setting[[]model.Version]{
		Value: enabled, Line: minVer.Line, Set: true, Implicit: minVer.Implicit,
	}

	s.Ciphers = local.ciphers
	s.Ciphersuites = local.suites
	s.Curves = local.curves
	s.DHBits = local.dhBits
	if local.noTickets.Set {
		s.SessionTicket = model.Explicit(false, local.noTickets.Line)
	} else {
		s.SessionTicket = model.Default(true)
	}
	if local.preferSrv.Set {
		s.PreferServer = local.preferSrv
	} else {
		s.PreferServer = model.Default(true) // HAProxy default: server order wins
	}
	return s, true
}

func (d haproxyDefaults) lowestNoLine() int {
	line := 0
	for _, l := range d.noVersions {
		if line == 0 || l < line {
			line = l
		}
	}
	return line
}
