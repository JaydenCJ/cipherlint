// Package policy holds cipherlint's dated best-practice tables. A profile is
// (name, date): `intermediate@2023-10` is the recommendation as it stood in
// October 2023, `intermediate@2026-01` as of January 2026. Dates are how
// cipherlint stays honest — TLS advice changes (OCSP stapling being the
// recent example), and a linter that silently moves the goalposts is worse
// than one that tells you which vintage of advice it is applying. Requesting
// a bare profile name resolves to the newest date.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

// Rec is a three-valued recommendation for a boolean knob.
type Rec int

const (
	Any     Rec = iota // no recommendation either way
	On                 // should be enabled
	Off                // should be disabled
	Retired            // was recommended once; now pointless (kept for dated tables)
)

// Profile is one dated row of the policy table.
type Profile struct {
	Name string // modern | intermediate | old
	Date string // YYYY-MM
	// Source is the citation for this table row, shown next to findings that
	// have no sharper citation (RFC, CVE) of their own.
	Source string

	MinVersion   model.Version // oldest version the profile tolerates
	RequireTLS13 bool          // TLS 1.3 must be among the enabled versions

	RequireFS   bool // forbid static-RSA key exchange
	RequireAEAD bool // forbid CBC/HMAC suites

	ServerPreference Rec // server-side cipher ordering
	SessionTickets   Rec // TLS session tickets (rotation-less tickets break FS)
	OCSPStapling     Rec // On (dated tables <= 2024) or Retired (2026+)

	MinDHBits  int      // minimum ephemeral DH parameter size
	Curves     []string // recommended ECDH curves/groups (normalized names); nil = any
	HSTSMinAge int64    // recommended minimum Strict-Transport-Security max-age
}

// ID returns the fully-qualified profile identifier, e.g. "modern@2026-01".
func (p Profile) ID() string { return p.Name + "@" + p.Date }

const (
	srcMozilla57 = "Mozilla server-side TLS v5.7 (2023-10)"
	src2026      = "cipherlint policy table 2026-01 (docs/rules.md)"
)

// mozillaCurves are the curves every dated table recommends.
var mozillaCurves = []string{"x25519", "secp256r1", "secp384r1"}

// table is the full dated policy set, oldest date first within each name.
var table = []Profile{
	{
		Name: "modern", Date: "2023-10", Source: srcMozilla57,
		MinVersion: model.TLS13, RequireTLS13: true,
		RequireFS: true, RequireAEAD: true,
		ServerPreference: Off, SessionTickets: Off, OCSPStapling: On,
		MinDHBits: 2048, Curves: mozillaCurves, HSTSMinAge: 63072000,
	},
	{
		Name: "intermediate", Date: "2023-10", Source: srcMozilla57,
		MinVersion: model.TLS12, RequireTLS13: true,
		RequireFS: true, RequireAEAD: true,
		ServerPreference: Off, SessionTickets: Off, OCSPStapling: On,
		MinDHBits: 2048, Curves: mozillaCurves, HSTSMinAge: 63072000,
	},
	{
		Name: "old", Date: "2023-10", Source: srcMozilla57,
		MinVersion: model.TLS10, RequireTLS13: true,
		RequireFS: false, RequireAEAD: false,
		ServerPreference: On, SessionTickets: Any, OCSPStapling: On,
		MinDHBits: 1024, Curves: nil, HSTSMinAge: 63072000,
	},
	{
		Name: "modern", Date: "2026-01", Source: src2026,
		MinVersion: model.TLS13, RequireTLS13: true,
		RequireFS: true, RequireAEAD: true,
		ServerPreference: Off, SessionTickets: Off, OCSPStapling: Retired,
		MinDHBits: 2048, Curves: mozillaCurves, HSTSMinAge: 63072000,
	},
	{
		Name: "intermediate", Date: "2026-01", Source: src2026,
		MinVersion: model.TLS12, RequireTLS13: true,
		RequireFS: true, RequireAEAD: true,
		ServerPreference: Off, SessionTickets: Off, OCSPStapling: Retired,
		MinDHBits: 2048, Curves: mozillaCurves, HSTSMinAge: 63072000,
	},
	{
		Name: "old", Date: "2026-01", Source: src2026,
		MinVersion: model.TLS10, RequireTLS13: true,
		RequireFS: false, RequireAEAD: false,
		ServerPreference: On, SessionTickets: Any, OCSPStapling: Retired,
		MinDHBits: 1024, Curves: nil, HSTSMinAge: 63072000,
	},
}

// List returns every profile, sorted by name then date (ascending), so
// output is deterministic.
func List() []Profile {
	out := make([]Profile, len(table))
	copy(out, table)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Date < out[j].Date
	})
	return out
}

// Resolve maps a profile spec — "intermediate" (newest date) or
// "intermediate@2023-10" (that exact vintage) — to its Profile.
func Resolve(spec string) (Profile, error) {
	name, date := spec, ""
	if i := strings.IndexByte(spec, '@'); i >= 0 {
		name, date = spec[:i], spec[i+1:]
	}
	name = strings.ToLower(strings.TrimSpace(name))

	var best *Profile
	for i := range table {
		p := &table[i]
		if p.Name != name {
			continue
		}
		if date != "" {
			if p.Date == date {
				return *p, nil
			}
			continue
		}
		if best == nil || p.Date > best.Date {
			best = p
		}
	}
	if best != nil {
		return *best, nil
	}
	if date != "" {
		var dates []string
		for _, p := range table {
			if p.Name == name {
				dates = append(dates, p.Date)
			}
		}
		if len(dates) > 0 {
			sort.Strings(dates)
			return Profile{}, fmt.Errorf("profile %q has no %s edition (available: %s)",
				name, date, strings.Join(dates, ", "))
		}
	}
	return Profile{}, fmt.Errorf("unknown profile %q (available: %s)", spec, strings.Join(NameList(), ", "))
}

// NameList returns the distinct profile names, sorted.
func NameList() []string {
	seen := map[string]bool{}
	var names []string
	for _, p := range table {
		if !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	return names
}

// NormalizeCurve maps the aliases the four dialects use onto one canonical
// name, so `prime256v1` (OpenSSL), `secp256r1` (IANA) and `P-256` (Caddy/Go)
// all compare equal.
func NormalizeCurve(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "x25519":
		return "x25519"
	case "x448":
		return "x448"
	case "prime256v1", "secp256r1", "p-256", "p256":
		return "secp256r1"
	case "secp384r1", "p-384", "p384":
		return "secp384r1"
	case "secp521r1", "p-521", "p521":
		return "secp521r1"
	case "ffdhe2048", "ffdhe3072", "ffdhe4096":
		return strings.ToLower(c)
	default:
		return strings.ToLower(strings.TrimSpace(c))
	}
}

// WeakCurves flags curves with < ~112-bit security or known implementation
// hazards; enabling any of them is an error under every profile.
var WeakCurves = map[string]string{
	"secp160r1":  "~80-bit security",
	"secp160r2":  "~80-bit security",
	"secp192r1":  "~96-bit security",
	"prime192v1": "~96-bit security",
	"secp224r1":  "below the 112-bit floor recommended since NIST SP 800-57",
	"sect163k1":  "~80-bit binary-field curve",
	"sect163r2":  "~80-bit binary-field curve",
}
