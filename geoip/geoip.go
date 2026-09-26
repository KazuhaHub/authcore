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
//     is a map {iso_code, names:{en:...}}, plus "city", "subdivisions" and a
//     "location" block {latitude, longitude, accuracy_radius} on city-level
//     databases.
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
	"math"
	"net"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Location is what a lookup can say about an address. Every field is
// optional: a country-level database fills only CountryCode and Country, and
// an address that is not in the database (or was never looked up) fills none.
//
// RegionCode, Latitude, Longitude and AccuracyRadiusKm are read only from the
// MaxMind schema's "subdivisions" and "location" keys, which city-level
// databases carry, and not every such database fills all four (the README
// lists which fills which). They were added after the first four fields, all
// omitempty, so a Location without them marshals to exactly the JSON it did
// before they existed.
//
// Latitude and Longitude are a pair, set together or not at all, and (0, 0)
// means there are none. They are where the database places the network, not
// where the device is: MaxMind documents them as not precise, standing for a
// larger area rather than a location, and AccuracyRadiusKm is that area's
// radius when the database gives one. Deciding what a distance between two
// lookups means (travel, sharing, nothing) is the caller's policy, not this
// package's. In JSON a coordinate that is exactly 0 is dropped by omitempty
// like any other zero, so a point on the equator arrives with "longitude"
// alone; read the missing one as 0.
type Location struct {
	CountryCode string `json:"country_code,omitempty"` // ISO 3166-1 alpha-2, upper-cased
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"` // state / province
	City        string `json:"city,omitempty"`
	// RegionCode is the region part of the first subdivision's ISO 3166-2
	// code, without the country prefix ("GD", not "CN-GD"), upper-cased: the
	// code for the subdivision Region names, when Region came from one.
	RegionCode string  `json:"region_code,omitempty"`
	Latitude   float64 `json:"latitude,omitempty"`  // WGS84 degrees, -90..90
	Longitude  float64 `json:"longitude,omitempty"` // WGS84 degrees, -180..180
	// AccuracyRadiusKm is the radius around (Latitude, Longitude) within
	// which the database expects the address to be. 0 means the database
	// gave none (DB-IP Lite documents none), not that the point is exact; it
	// is always 0 when there are no coordinates.
	AccuracyRadiusKm int `json:"accuracy_radius_km,omitempty"`
}

// Empty reports whether the lookup found nothing worth showing. Useful for
// callers that want to distinguish "resolved to nothing" from "has a value"
// without comparing every field themselves.
//
// It looks only at the four place-name fields. A Location holding
// coordinates or a RegionCode but no name still reports Empty, as it would
// have before those fields existed, so adding them changed no caller's
// answer.
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
			out.RegionCode = strings.ToUpper(str(first["iso_code"]))
		}
	}
	if out.Region == "" {
		out.Region = str(rec["region"])
	}

	// Only the MaxMind schema has a location block; ipinfo Lite has no
	// coordinates at all, so its records never reach this branch.
	if loc, ok := rec["location"].(map[string]any); ok {
		out.Latitude, out.Longitude, out.AccuracyRadiusKm = coordinates(loc)
	}
	return out
}

// maxAccuracyRadiusKm is the largest accuracy_radius taken at face value:
// half the Earth's equatorial circumference (about 20,037 km), the farthest
// two points on its surface can be apart. A larger radius cannot be an
// accuracy figure, so it is dropped as corrupt rather than handed to a caller
// to subtract from a distance.
const maxAccuracyRadiusKm = 20037

// coordinates reads a "location" block into a latitude/longitude pair and an
// accuracy radius, following the same rule as the rest of mapRecord: a value
// of the wrong type or out of range is data this package does not have, so it
// becomes a zero, never an error, and the rest of the record is unaffected.
//
// The pair is validated together. If either half is missing, of the wrong
// type or out of range, neither is returned: a lone latitude read with a zero
// longitude would be a real point on the prime meridian, and a caller
// computing a distance from it would have no way to tell. (0, 0) is treated
// as no answer, since the zero value already means that, and the radius is
// returned only alongside a pair, because it is a distance from that point.
// A fractional radius is rounded up, so the field never claims more precision
// than the database did.
func coordinates(loc map[string]any) (lat, lon float64, radiusKm int) {
	lat, latOK := number(loc["latitude"])
	lon, lonOK := number(loc["longitude"])
	if !latOK || !lonOK || lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
		return 0, 0, 0
	}
	if r, ok := number(loc["accuracy_radius"]); ok && r >= 0 && r <= maxAccuracyRadiusKm {
		radiusKm = int(math.Ceil(r))
	}
	return lat, lon, radiusKm
}

// number reads a decoded numeric value as a float64. Decoding into
// map[string]any, maxminddb-golang v1 hands back a MaxMind DB double as
// float64, a single-precision float as float32, every unsigned width
// (accuracy_radius is a uint16 on disk) as uint64, and an int32 as int; int64
// is accepted too, for a writer or decoder that widens differently. Any
// other type, NaN and both infinities report false.
func number(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case uint64:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
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
