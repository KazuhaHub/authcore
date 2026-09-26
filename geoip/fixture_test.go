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
	// granularity, with the "location" block and subdivision iso_code a real
	// GeoLite2-City record carries. The wire types are MaxMind's own: double
	// for the coordinates, uint16 for accuracy_radius.
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
				"iso_code": mmdbtype.String("TS"),
				"names": mmdbtype.Map{
					"en": mmdbtype.String("Test State"),
				},
			},
		},
		"location": mmdbtype.Map{
			"latitude":        mmdbtype.Float64(40.5),
			"longitude":       mmdbtype.Float64(-89.25),
			"accuracy_radius": mmdbtype.Uint16(20),
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

// coordinateCase is one record of buildCoordinatesFixture: the network it is
// inserted at, an address inside that network, the record, and what Lookup
// must return for it.
type coordinateCase struct {
	name string
	cidr string
	ip   string
	rec  mmdbtype.Map
	want Location
}

// coordinateCases are the records the "location" and subdivision iso_code
// handling is tested against end to end: a DB-IP-shaped record, and records
// whose values have a type or range no real database should write. They go
// through a real .mmdb rather than a hand-built map because what matters is
// the Go type maxminddb-golang v1 hands back for each wire type (a uint16
// arrives as uint64, an int32 as int, a float as float32), and only the real
// decoder says that.
//
// They live in a database of their own so that buildFixture's records, which
// the Watcher tests also read, keep their exact shape. Every network is a /28
// inside TEST-NET-1 (RFC 5737).
func coordinateCases() []coordinateCase {
	us := mmdbtype.Map{
		"iso_code": mmdbtype.String("US"),
		"names":    mmdbtype.Map{"en": mmdbtype.String("United States")},
	}
	usOnly := Location{CountryCode: "US", Country: "United States"}
	return []coordinateCase{
		{
			// DB-IP City Lite's documented schema: subdivision names only,
			// and a location block with latitude and longitude but no
			// accuracy_radius.
			name: "dbip-shape/no-radius",
			cidr: "192.0.2.0/28",
			ip:   "192.0.2.1",
			rec: mmdbtype.Map{
				"country": mmdbtype.Map{
					"iso_code": mmdbtype.String("CN"),
					"names":    mmdbtype.Map{"en": mmdbtype.String("China")},
				},
				"city": mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Guangzhou")}},
				"subdivisions": mmdbtype.Slice{
					mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Guangdong")}},
				},
				"location": mmdbtype.Map{
					"latitude":  mmdbtype.Float64(23.125),
					"longitude": mmdbtype.Float64(113.25),
				},
			},
			want: Location{
				CountryCode: "CN", Country: "China", Region: "Guangdong", City: "Guangzhou",
				Latitude: 23.125, Longitude: 113.25,
			},
		},
		{
			name: "string-latitude/no-coordinates",
			cidr: "192.0.2.16/28",
			ip:   "192.0.2.17",
			rec: mmdbtype.Map{
				"country": us,
				"location": mmdbtype.Map{
					"latitude":        mmdbtype.String("40.5"),
					"longitude":       mmdbtype.Float64(-89.25),
					"accuracy_radius": mmdbtype.Uint16(20),
				},
			},
			want: usOnly,
		},
		{
			name: "negative-radius/coordinates-kept",
			cidr: "192.0.2.32/28",
			ip:   "192.0.2.33",
			rec: mmdbtype.Map{
				"country": us,
				"location": mmdbtype.Map{
					"latitude":        mmdbtype.Float64(40.5),
					"longitude":       mmdbtype.Float64(-89.25),
					"accuracy_radius": mmdbtype.Int32(-5),
				},
			},
			want: Location{CountryCode: "US", Country: "United States", Latitude: 40.5, Longitude: -89.25},
		},
		{
			name: "latitude-200/region-code-kept",
			cidr: "192.0.2.48/28",
			ip:   "192.0.2.49",
			rec: mmdbtype.Map{
				"country": us,
				"subdivisions": mmdbtype.Slice{
					mmdbtype.Map{
						"iso_code": mmdbtype.String("TS"),
						"names":    mmdbtype.Map{"en": mmdbtype.String("Test State")},
					},
				},
				"location": mmdbtype.Map{
					"latitude":        mmdbtype.Float64(200),
					"longitude":       mmdbtype.Float64(-89.25),
					"accuracy_radius": mmdbtype.Uint16(20),
				},
			},
			want: Location{CountryCode: "US", Country: "United States", Region: "Test State", RegionCode: "TS"},
		},
		{
			name: "radius-wider-than-the-earth",
			cidr: "192.0.2.64/28",
			ip:   "192.0.2.65",
			rec: mmdbtype.Map{
				"country": us,
				"location": mmdbtype.Map{
					"latitude":        mmdbtype.Float64(40.5),
					"longitude":       mmdbtype.Float64(-89.25),
					"accuracy_radius": mmdbtype.Uint16(65535),
				},
			},
			want: Location{CountryCode: "US", Country: "United States", Latitude: 40.5, Longitude: -89.25},
		},
		{
			// A single-precision float and a uint32 are legal MaxMind DB
			// types, though not the double and uint16 the vendors document
			// for these keys; they decode as float32 and uint64, and are
			// still read.
			name: "float32-coordinates/uint32-radius",
			cidr: "192.0.2.80/28",
			ip:   "192.0.2.81",
			rec: mmdbtype.Map{
				"country": us,
				"location": mmdbtype.Map{
					"latitude":        mmdbtype.Float32(40.5),
					"longitude":       mmdbtype.Float32(-89.25),
					"accuracy_radius": mmdbtype.Uint32(100),
				},
			},
			want: Location{
				CountryCode: "US", Country: "United States",
				Latitude: 40.5, Longitude: -89.25, AccuracyRadiusKm: 100,
			},
		},
		{
			name: "location-not-a-map",
			cidr: "192.0.2.96/28",
			ip:   "192.0.2.97",
			rec: mmdbtype.Map{
				"country":  us,
				"location": mmdbtype.String("40.5,-89.25"),
			},
			want: usOnly,
		},
		{
			name: "region-code-upper-cased-and-trimmed",
			cidr: "192.0.2.112/28",
			ip:   "192.0.2.113",
			rec: mmdbtype.Map{
				"country": us,
				"subdivisions": mmdbtype.Slice{
					mmdbtype.Map{
						"iso_code": mmdbtype.String(" ts "),
						"names":    mmdbtype.Map{"en": mmdbtype.String("Test State")},
					},
				},
			},
			want: Location{CountryCode: "US", Country: "United States", Region: "Test State", RegionCode: "TS"},
		},
	}
}

// buildCoordinatesFixture writes coordinateCases into a .mmdb and returns its
// path.
func buildCoordinatesFixture(t *testing.T) string {
	t.Helper()

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "Test-City-Coordinates",
		IncludeReservedNetworks: true,
		RecordSize:              24,
		Languages:               []string{"en"},
	})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	for _, c := range coordinateCases() {
		_, network, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c.cidr, err)
		}
		if err := w.Insert(network, c.rec); err != nil {
			t.Fatalf("Insert(%q): %v", c.cidr, err)
		}
	}

	path := filepath.Join(t.TempDir(), "coordinates.mmdb")
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
