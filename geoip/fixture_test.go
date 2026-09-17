package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// buildFixture writes a small, real .mmdb file covering both schemas this
// package understands, plus an unmapped range for the "miss" case, and
// returns its path. Built fresh per test (not embedded as a binary asset) so
// the fixture's shape stays next to the tests that depend on it.
//
// All test networks are RFC 5737 / RFC 3849 documentation ranges — never a
// real, reachable address — as mmdbwriter treats every one of them as
// "reserved" by default, hence IncludeReservedNetworks below.
func buildFixture(t *testing.T, dbType string) string {
	t.Helper()

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		IncludeReservedNetworks: true,
		RecordSize:              24,
		Languages:               []string{"en", "ja"},
	})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}

	insert := func(cidr string, rec mmdbtype.DataType) {
		t.Helper()
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		if err := w.Insert(network, rec); err != nil {
			t.Fatalf("Insert(%q): %v", cidr, err)
		}
	}

	// TEST-NET-1 (RFC 5737): MaxMind / GeoLite2 nested-object schema, city
	// granularity.
	insert("192.0.2.0/24", mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("US"),
			"names": mmdbtype.Map{
				"en": mmdbtype.String("United States"),
			},
		},
		"city": mmdbtype.Map{
			"names": mmdbtype.Map{
				"en": mmdbtype.String("Testville"),
			},
		},
		"subdivisions": mmdbtype.Slice{
			mmdbtype.Map{
				"names": mmdbtype.Map{
					"en": mmdbtype.String("Test State"),
				},
			},
		},
	})

	// TEST-NET-2 (RFC 5737): ipinfo Lite flat-string schema, country-only.
	insert("198.51.100.0/24", mmdbtype.Map{
		"country":      mmdbtype.String("Japan"),
		"country_code": mmdbtype.String("jp"), // lower-case, exercises upper-casing
	})

	// 2001:db8::/32 (RFC 3849): IPv6, MaxMind schema with a non-English-only
	// names map (no "en") to exercise the language-fallback path.
	insert("2001:db8::/32", mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("DE"),
			"names": mmdbtype.Map{
				"ja": mmdbtype.String("ドイツ"),
			},
		},
	})

	// TEST-NET-3 (RFC 5737) is deliberately left unmapped: the "miss" case.

	path := filepath.Join(t.TempDir(), "fixture.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// touchLarger replaces path's content with content whose size differs from
// whatever is there, and advances its mtime, so Watcher's change-detection
// (which compares both) reliably sees it as new even within the same
// filesystem timestamp resolution.
//
// It replaces the file via write-to-temp + os.Rename — an ATOMIC swap of the
// directory entry — rather than truncating and rewriting path in place. That
// distinction is load-bearing, not stylistic: a Reader may still have path
// memory-mapped for an in-flight Lookup; renaming a new inode over the
// directory entry leaves that mapping pointing at the old (now unlinked but
// still open, and unchanged) inode, so the in-flight read completes safely.
// Rewriting the SAME inode's bytes while it is mapped has no such guarantee —
// a concurrent reader can fault (SIGBUS) mid-read. This is exactly why real
// callers (this package's watcher_test.go included) must always replace a
// watched database file by atomic rename, never by in-place write; both
// PSP's and RP's production updaters already do this correctly.
func touchLarger(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", tmp, err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(tmp, future, future); err != nil {
		t.Fatalf("chtimes %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename %s -> %s: %v", tmp, path, err)
	}
}
