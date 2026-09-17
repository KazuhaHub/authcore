// Package geoip resolves an IP address to a place using a local MaxMind-format
// (.mmdb) database. Lookups are fully offline: the memory-mapped file IS the
// lookup, so there is no per-address network call and no cache to keep
// coherent with anything.
//
// Offline is a requirement here, not a preference: the addresses handed to
// this package are often a caller's own untrusted visitors (including people
// who never authenticated), so sending them to a third party to be geolocated
// would hand that list to somebody else.
//
// One Reader reads either of the two common free database schemas, because
// they disagree about the shape of the same field:
//
//   - MaxMind GeoLite2 / GeoIP2 / DB-IP Lite: nested objects, where "country"
//     is a map {iso_code, names:{en:...}}, plus "city" and "subdivisions" on
//     city-level databases.
//   - ipinfo Lite: flat strings, where "country" is the country NAME and
//     "country_code" is the ISO code; country granularity only.
//
// They collide on the "country" key (map vs. string), so a record is decoded
// into a generic map and branched on the runtime type rather than into one
// fixed struct. That also means a future MaxMind-compatible database works
// without a change here.
//
// This package knows nothing about who is asking or why: it maps an IP string
// to a Location and nothing else. Anything above that — whether a lookup is
// even attempted, what a caller does with the result, how failures are
// surfaced to an operator — is the caller's concern, not this package's.
package geoip

import (
	"net"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Location is what a lookup can say about an address. Every field is
// optional: a country-level database fills only CountryCode and Country, and
// an address that is not in the database (or was never looked up) fills none.
type Location struct {
	CountryCode string `json:"country_code,omitempty"` // ISO 3166-1 alpha-2, upper-cased
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"` // state / province
	City        string `json:"city,omitempty"`
}

// Empty reports whether the lookup found nothing worth showing. Useful for
// callers that want to distinguish "resolved to nothing" from "has a value"
// without comparing every field themselves.
func (l Location) Empty() bool {
	return l.CountryCode == "" && l.Country == "" && l.Region == "" && l.City == ""
}

// DBInfo describes a loaded database, e.g. for an admin status view.
type DBInfo struct {
	Type        string `json:"type"`        // Metadata.DatabaseType, e.g. "GeoLite2-City"
	BuildEpoch  uint   `json:"build_epoch"` // unix seconds the database was built
	Granularity string `json:"granularity"` // "city" or "country"
}

// Reader wraps an open .mmdb database. Safe for concurrent Lookup calls (the
// underlying maxminddb.Reader is) — a nil *Reader is also safe to call every
// method on, answering as "no database loaded" rather than panicking, so a
// caller that has not opened one yet does not need a nil check at every call
// site. The caller owns the Reader's lifecycle (open, close, reload).
type Reader struct {
	db *maxminddb.Reader
}

// Open opens an .mmdb file.
func Open(path string) (*Reader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Reader{db: db}, nil
}

// Close releases the database. Safe to call on a nil Reader.
func (r *Reader) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// Info returns metadata about the loaded database.
func (r *Reader) Info() DBInfo {
	if r == nil || r.db == nil {
		return DBInfo{}
	}
	m := r.db.Metadata
	return DBInfo{
		Type:        m.DatabaseType,
		BuildEpoch:  m.BuildEpoch,
		Granularity: granularityOf(m.DatabaseType),
	}
}

func granularityOf(dbType string) string {
	if strings.Contains(strings.ToLower(dbType), "city") {
		return "city"
	}
	return "country"
}

// Lookup resolves one address. An unparseable, private, or unmapped address
// returns a zero Location and a nil error, deliberately: "we do not know
// where this is" is the ordinary answer for a LAN address or a miss, not a
// failure, and making every caller distinguish it from a real error would put
// the same branch at every call site to reach the same result. A non-nil
// error means the database itself could not be read (a corrupt file, for
// example) — not that the address was not found.
func (r *Reader) Lookup(ip string) (Location, error) {
	if r == nil || r.db == nil {
		return Location{}, nil
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || !IsResolvable(ip) {
		return Location{}, nil
	}
	var rec map[string]any
	if err := r.db.Lookup(parsed, &rec); err != nil {
		return Location{}, err
	}
	return mapRecord(rec), nil
}

// IsResolvable reports whether ip is a routable, unicast address worth
// looking up. A loopback, private (RFC 1918 / ULA), link-local, unspecified,
// or multicast address is never in a geolocation database, and looking one up
// would only produce an empty answer more slowly. Works for both IPv4 and
// IPv6.
func IsResolvable(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	return !p.IsLoopback() && !p.IsPrivate() && !p.IsUnspecified() &&
		!p.IsLinkLocalUnicast() && !p.IsLinkLocalMulticast() && !p.IsMulticast()
}

// mapRecord flattens a decoded mmdb record (either schema) into a Location.
func mapRecord(rec map[string]any) Location {
	if rec == nil {
		return Location{}
	}
	var out Location
	switch c := rec["country"].(type) {
	case map[string]any: // MaxMind / GeoLite2 / DB-IP schema
		out.CountryCode = str(c["iso_code"])
		out.Country = localizedName(c)
	case string: // ipinfo Lite schema: country is the NAME, code in its own field
		out.Country = c
		out.CountryCode = str(rec["country_code"])
	default:
		// Some ipinfo variants key the code as country_code with no "country".
		out.CountryCode = str(rec["country_code"])
		out.Country = str(rec["country_name"])
	}
	if out.CountryCode == "" {
		out.CountryCode = str(rec["country_code"])
	}
	out.CountryCode = strings.ToUpper(out.CountryCode)

	if city, ok := rec["city"].(map[string]any); ok {
		out.City = localizedName(city)
	} else {
		out.City = str(rec["city"])
	}
	// Subdivisions run outermost-first; the first is the state/province.
	if subs, ok := rec["subdivisions"].([]any); ok && len(subs) > 0 {
		if first, ok := subs[0].(map[string]any); ok {
			out.Region = localizedName(first)
		}
	}
	if out.Region == "" {
		out.Region = str(rec["region"])
	}
	return out
}

// localizedName extracts the English display name from a maxminddb "names"
// map (or a flat "name" string), falling back to whatever single name is
// present so a non-English-only database still shows something. The client
// is expected to localize the COUNTRY itself from the ISO code, so this only
// needs to be stable, not translated.
func localizedName(m map[string]any) string {
	names, ok := m["names"].(map[string]any)
	if !ok {
		return str(m["name"])
	}
	if v := str(names["en"]); v != "" {
		return v
	}
	for _, v := range names {
		if sv := str(v); sv != "" {
			return sv
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
