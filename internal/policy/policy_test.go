// Policy table tests: date resolution, pinning, and the guarantees the
// dated-table design makes (newer vintages may change advice, and both
// vintages stay addressable forever).
package policy

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/cipherlint/internal/model"
)

func TestResolveBareNamePicksNewestDate(t *testing.T) {
	p, err := Resolve("intermediate")
	if err != nil {
		t.Fatal(err)
	}
	if p.Date != "2026-01" {
		t.Fatalf("bare name resolved to %s, want the newest date 2026-01", p.Date)
	}
}

func TestResolvePinnedDateAndCase(t *testing.T) {
	p, err := Resolve("intermediate@2023-10")
	if err != nil {
		t.Fatal(err)
	}
	if p.Date != "2023-10" || p.Name != "intermediate" {
		t.Fatalf("pin failed: %s", p.ID())
	}
	if _, err := Resolve("Modern"); err != nil {
		t.Fatalf("mixed-case profile name should resolve: %v", err)
	}
}

func TestResolveErrorsAreActionable(t *testing.T) {
	// Unknown name: the error lists the available names.
	_, err := Resolve("paranoid")
	if err == nil || !strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("error should list the available names, got %v", err)
	}
	// Known name, unknown date: the error lists the available editions.
	_, err = Resolve("modern@1999-12")
	if err == nil || !strings.Contains(err.Error(), "2023-10") || !strings.Contains(err.Error(), "2026-01") {
		t.Fatalf("error should list available editions, got %v", err)
	}
}

func TestDatedTablesDifferOnStapling(t *testing.T) {
	// The whole point of dating tables: the 2023 vintage recommends OCSP
	// stapling; the 2026 vintage marks it retired. Both remain addressable.
	p2023, _ := Resolve("intermediate@2023-10")
	p2026, _ := Resolve("intermediate@2026-01")
	if p2023.OCSPStapling != On {
		t.Fatalf("2023-10 stapling = %v, want On", p2023.OCSPStapling)
	}
	if p2026.OCSPStapling != Retired {
		t.Fatalf("2026-01 stapling = %v, want Retired", p2026.OCSPStapling)
	}
}

func TestListIsSortedCompleteAndOrdered(t *testing.T) {
	l := List()
	if len(l) != 6 {
		t.Fatalf("expected 6 dated profiles, got %d", len(l))
	}
	for i := 1; i < len(l); i++ {
		a, b := l[i-1], l[i]
		if a.Name > b.Name || (a.Name == b.Name && a.Date > b.Date) {
			t.Fatalf("List not sorted at %d: %s before %s", i, a.ID(), b.ID())
		}
	}
	// Protocol floors must strictly descend across the three names.
	m, _ := Resolve("modern")
	in, _ := Resolve("intermediate")
	o, _ := Resolve("old")
	if !(m.MinVersion > in.MinVersion && in.MinVersion > o.MinVersion) {
		t.Fatalf("floors must strictly descend: modern=%v intermediate=%v old=%v",
			m.MinVersion, in.MinVersion, o.MinVersion)
	}
	if m.MinVersion != model.TLS13 || in.MinVersion != model.TLS12 {
		t.Fatal("modern must be TLS 1.3-only and intermediate TLS 1.2+")
	}
}

func TestNormalizeCurveAliases(t *testing.T) {
	cases := map[string]string{
		"X25519":     "x25519",
		"prime256v1": "secp256r1",
		"P-256":      "secp256r1",
		"secp384r1":  "secp384r1",
		"P-384":      "secp384r1",
	}
	for in, want := range cases {
		if got := NormalizeCurve(in); got != want {
			t.Fatalf("NormalizeCurve(%q) = %q, want %q", in, got, want)
		}
	}
}
