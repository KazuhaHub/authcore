package geoip

import (
	"encoding/json"
	"math"
	"testing"
)

// ---- dual-schema decoding (synthetic records) --------------------------
//
// mapRecord is the heart of the dual-schema support: MaxMind's "country" is a
// nested object, ipinfo Lite's "country" is a plain string. Both must flatten
// to the same Location shape. Exercised directly against hand-built records
// here; the end-to-end path (a real .mmdb file) is covered below.

func TestMapRecord_MaxMindSchema(t *testing.T) {
	rec := map[string]any{
		"country": map[string]any{
			"iso_code": "HK",
			"names":    map[string]any{"en": "Hong Kong", "zh-CN": "香港"},
		},
		"city": map[string]any{"names": map[string]any{"en": "Central"}},
		"subdivisions": []any{
			map[string]any{"names": map[string]any{"en": "Central and Western"}},
		},
	}
	got := mapRecord(rec)
	if got.CountryCode != "HK" || got.Country != "Hong Kong" {
		t.Fatalf("country = %q/%q, want HK/Hong Kong", got.CountryCode, got.Country)
	}
	if got.City != "Central" {
		t.Fatalf("city = %q, want Central", got.City)
	}
	if got.Region != "Central and Western" {
		t.Fatalf("region = %q, want Central and Western", got.Region)
	}
	if got.Empty() {
		t.Fatal("Empty() = true for a fully-populated record")
	}
}

func TestMapRecord_IPinfoSchema(t *testing.T) {
	rec := map[string]any{
		"country":      "Hong Kong", // ipinfo: country is the NAME (string)
		"country_code": "hk",        // lowercase → normalized to upper
		"continent":    "Asia",
	}
	got := mapRecord(rec)
	if got.CountryCode != "HK" {
		t.Fatalf("country_code = %q, want HK (upper-normalized)", got.CountryCode)
	}
	if got.Country != "Hong Kong" {
		t.Fatalf("country = %q, want Hong Kong", got.Country)
	}
	if got.City != "" || got.Region != "" {
		t.Fatalf("ipinfo Lite has no city/region; got city=%q region=%q", got.City, got.Region)
	}
}

func TestMapRecord_CountryCodeOnlyVariant(t *testing.T) {
	// Some ipinfo-style variants key the code as country_code with no
	// "country" entry at all.
	rec := map[string]any{
		"country_code": "fr",
		"country_name": "France",
	}
	got := mapRecord(rec)
	if got.CountryCode != "FR" || got.Country != "France" {
		t.Fatalf("got %+v, want FR/France", got)
	}
}

func TestMapRecord_CityAndRegionAsPlainStrings(t *testing.T) {
	// A schema variant with flat city/region strings instead of nested
	// {names:{en:...}} objects must still resolve.
	rec := map[string]any{
		"country": map[string]any{
			"iso_code": "US",
			"names":    map[string]any{"en": "United States"},
		},
		"city":   "Springfield",
		"region": "Illinois",
	}
	got := mapRecord(rec)
	if got.City != "Springfield" || got.Region != "Illinois" {
		t.Fatalf("got city=%q region=%q, want Springfield/Illinois", got.City, got.Region)
	}
}

func TestMapRecord_NameFallbackWithoutEnglish(t *testing.T) {
	// No "en" key — fall back to any available language so a non-en-only DB
	// still shows something.
	rec := map[string]any{
		"country": map[string]any{"iso_code": "JP", "names": map[string]any{"ja": "日本"}},
	}
	if got := mapRecord(rec).Country; got != "日本" {
		t.Fatalf("country name fallback = %q, want 日本", got)
	}
}

func TestMapRecord_Nil(t *testing.T) {
	if got := mapRecord(nil); !got.Empty() {
		t.Fatalf("mapRecord(nil) = %+v, want empty", got)
	}
}

// ---- coordinates and region code (synthetic records) --------------------
//
// The values below are the Go types maxminddb-golang v1 produces when it
// decodes into map[string]any: a double arrives as float64, every unsigned
// width (uint16 accuracy_radius included) as uint64, an int32 as int, a
// single-precision float as float32. The end-to-end test further down
// confirms those types against the real decoder.

func TestMapRecord_MaxMindCoordinates(t *testing.T) {
	rec := map[string]any{
		"country": map[string]any{
			"iso_code": "CN",
			"names":    map[string]any{"en": "China"},
		},
		"city": map[string]any{"names": map[string]any{"en": "Guangzhou"}},
		"subdivisions": []any{
			map[string]any{"iso_code": "GD", "names": map[string]any{"en": "Guangdong"}},
		},
		"location": map[string]any{
			"latitude":        23.125,
			"longitude":       113.25,
			"accuracy_radius": uint64(50),
			"time_zone":       "Asia/Shanghai",
		},
	}
	want := Location{
		CountryCode: "CN", Country: "China", Region: "Guangdong", City: "Guangzhou",
		RegionCode: "GD", Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 50,
	}
	if got := mapRecord(rec); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMapRecord_DBIPCoordinatesWithoutRadius(t *testing.T) {
	// DB-IP City Lite documents latitude and longitude, no accuracy_radius,
	// and subdivision names only.
	rec := map[string]any{
		"country":      map[string]any{"iso_code": "CN", "names": map[string]any{"en": "China"}},
		"subdivisions": []any{map[string]any{"names": map[string]any{"en": "Guangdong"}}},
		"location":     map[string]any{"latitude": 23.125, "longitude": 113.25},
	}
	want := Location{
		CountryCode: "CN", Country: "China", Region: "Guangdong",
		Latitude: 23.125, Longitude: 113.25,
	}
	if got := mapRecord(rec); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMapRecord_CountryOnlyHasNoCoordinates(t *testing.T) {
	rec := map[string]any{
		"country": map[string]any{"iso_code": "DE", "names": map[string]any{"en": "Germany"}},
	}
	if got, want := mapRecord(rec), (Location{CountryCode: "DE", Country: "Germany"}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMapRecord_IPinfoLiteUnchanged(t *testing.T) {
	// Every field ipinfo Lite ships. None of them is a coordinate or a
	// subdivision, so the result must be exactly what it was before those
	// fields existed: the whole struct is compared, not the fields of
	// interest, so a key that starts leaking into a new field fails here.
	rec := map[string]any{
		"asn":            "AS64496", // RFC 5398 documentation ASN
		"as_name":        "Example Networks",
		"as_domain":      "example.com",
		"country_code":   "hk",
		"country":        "Hong Kong",
		"continent_code": "AS",
		"continent":      "Asia",
	}
	if got, want := mapRecord(rec), (Location{CountryCode: "HK", Country: "Hong Kong"}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMapRecord_CoordinateNumericTypes(t *testing.T) {
	cases := []struct {
		name     string
		lat, lon any
		radius   any
		want     Location
	}{
		{"float64", 23.125, 113.25, uint64(50), Location{Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 50}},
		{"float32", float32(23.125), float32(113.25), uint64(50), Location{Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 50}},
		{"uint64", uint64(23), uint64(113), uint64(50), Location{Latitude: 23, Longitude: 113, AccuracyRadiusKm: 50}},
		{"int", int(-23), int(-113), int(50), Location{Latitude: -23, Longitude: -113, AccuracyRadiusKm: 50}},
		{"int64", int64(-23), int64(-113), int64(50), Location{Latitude: -23, Longitude: -113, AccuracyRadiusKm: 50}},
		{"bounds-inclusive", 90.0, -180.0, uint64(0), Location{Latitude: 90, Longitude: -180}},
		// A fractional radius is rounded up, never down, so the field never
		// claims more precision than the database did.
		{"fractional-radius", 23.125, 113.25, 2.1, Location{Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 3}},
		{"radius-at-half-circumference", 23.125, 113.25, uint64(20037), Location{Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 20037}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := map[string]any{"location": map[string]any{
				"latitude": c.lat, "longitude": c.lon, "accuracy_radius": c.radius,
			}}
			if got := mapRecord(rec); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMapRecord_UnusableCoordinates(t *testing.T) {
	// Whatever is wrong with the location block, the rest of the record is
	// still read and nothing panics. Latitude and longitude are a pair: if
	// either is unusable, neither is set, because half a coordinate read as
	// its zero would be a real point on the equator or the prime meridian.
	// The radius is set only alongside a pair, since it is a distance from
	// that point.
	named := Location{CountryCode: "US", Country: "United States", Region: "Test State", RegionCode: "TS"}
	withPair := named
	withPair.Latitude, withPair.Longitude = 40.5, -89.25

	cases := []struct {
		name     string
		location any
		want     Location
	}{
		{"string-latitude", map[string]any{"latitude": "40.5", "longitude": -89.25, "accuracy_radius": uint64(20)}, named},
		{"latitude-200", map[string]any{"latitude": 200.0, "longitude": -89.25, "accuracy_radius": uint64(20)}, named},
		{"latitude-below-minus-90", map[string]any{"latitude": -90.5, "longitude": -89.25}, named},
		{"longitude-above-180", map[string]any{"latitude": 40.5, "longitude": 180.5}, named},
		{"latitude-nan", map[string]any{"latitude": math.NaN(), "longitude": -89.25}, named},
		{"longitude-inf", map[string]any{"latitude": 40.5, "longitude": math.Inf(1)}, named},
		{"latitude-bool", map[string]any{"latitude": true, "longitude": -89.25}, named},
		{"longitude-missing", map[string]any{"latitude": 40.5, "accuracy_radius": uint64(20)}, named},
		{"radius-without-coordinates", map[string]any{"accuracy_radius": uint64(20)}, named},
		// (0, 0) is where a database with no answer puts one, and the
		// zero value already means "no coordinates": a radius around it
		// would describe nothing.
		{"null-island", map[string]any{"latitude": 0.0, "longitude": 0.0, "accuracy_radius": uint64(20)}, named},
		{"negative-radius-int", map[string]any{"latitude": 40.5, "longitude": -89.25, "accuracy_radius": int(-5)}, withPair},
		{"negative-radius-float", map[string]any{"latitude": 40.5, "longitude": -89.25, "accuracy_radius": -0.5}, withPair},
		{"radius-wider-than-the-earth", map[string]any{"latitude": 40.5, "longitude": -89.25, "accuracy_radius": uint64(20038)}, withPair},
		{"radius-nan", map[string]any{"latitude": 40.5, "longitude": -89.25, "accuracy_radius": math.NaN()}, withPair},
		{"radius-string", map[string]any{"latitude": 40.5, "longitude": -89.25, "accuracy_radius": "20"}, withPair},
		{"location-a-string", "40.5,-89.25", named},
		{"location-a-slice", []any{40.5, -89.25}, named},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := map[string]any{
				"country": map[string]any{"iso_code": "US", "names": map[string]any{"en": "United States"}},
				"subdivisions": []any{
					map[string]any{"iso_code": "TS", "names": map[string]any{"en": "Test State"}},
				},
				"location": c.location,
			}
			if got := mapRecord(rec); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMapRecord_RegionCode(t *testing.T) {
	cases := []struct {
		name string
		subs any
		want string
	}{
		{"upper-cased-and-trimmed", []any{map[string]any{"iso_code": " gd "}}, "GD"},
		{"first-subdivision-only", []any{map[string]any{"iso_code": "ENG"}, map[string]any{"iso_code": "LND"}}, "ENG"},
		{"no-iso-code", []any{map[string]any{"names": map[string]any{"en": "Guangdong"}}}, ""},
		{"iso-code-not-a-string", []any{map[string]any{"iso_code": uint64(44)}}, ""},
		{"no-subdivisions", []any{}, ""},
		{"subdivision-not-a-map", []any{"GD"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mapRecord(map[string]any{"subdivisions": c.subs}).RegionCode; got != c.want {
				t.Fatalf("RegionCode = %q, want %q", got, c.want)
			}
		})
	}
}

// ---- JSON shape -----------------------------------------------------------

func TestLocation_JSON(t *testing.T) {
	// A consumer that aliases Location and serializes it (RP's audit output
	// does) must see the same bytes as before for a record with no
	// coordinates: every new key is omitempty.
	old, err := json.Marshal(Location{CountryCode: "US", Country: "United States", Region: "Test State", City: "Testville"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"country_code":"US","country":"United States","region":"Test State","city":"Testville"}`; string(old) != want {
		t.Fatalf("got %s, want %s", old, want)
	}

	full, err := json.Marshal(Location{
		CountryCode: "CN", RegionCode: "GD", Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"country_code":"CN","region_code":"GD","latitude":23.125,"longitude":113.25,"accuracy_radius_km":50}`; string(full) != want {
		t.Fatalf("got %s, want %s", full, want)
	}
}

// ---- IsResolvable --------------------------------------------------------

func TestIsResolvable(t *testing.T) {
	cases := map[string]bool{
		"192.0.2.1":    true,  // RFC 5737 TEST-NET-1 — publicly routable shape
		"198.51.100.1": true,  // RFC 5737 TEST-NET-2 — publicly routable shape
		"2001:db8::1":  true,  // RFC 3849 documentation range, still a public shape
		"192.168.1.1":  false, // private
		"10.0.0.5":     false, // private
		"127.0.0.1":    false, // loopback
		"::1":          false, // loopback
		"169.254.1.1":  false, // link-local
		"0.0.0.0":      false, // unspecified
		"224.0.0.1":    false, // multicast
		"ff02::1":      false, // IPv6 multicast
		"":             false,
		"not-an-ip":    false,
	}
	for ip, want := range cases {
		if got := IsResolvable(ip); got != want {
			t.Errorf("IsResolvable(%q) = %v, want %v", ip, got, want)
		}
	}
}

// ---- Reader / DBInfo nil-safety -----------------------------------------

func TestReader_NilSafe(t *testing.T) {
	var r *Reader
	if err := r.Close(); err != nil {
		t.Fatalf("(*Reader)(nil).Close() = %v, want nil", err)
	}
	if info := r.Info(); info != (DBInfo{}) {
		t.Fatalf("(*Reader)(nil).Info() = %+v, want zero value", info)
	}
	loc, err := r.Lookup("192.0.2.1")
	if err != nil || !loc.Empty() {
		t.Fatalf("(*Reader)(nil).Lookup() = %+v, %v; want empty, nil", loc, err)
	}
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open("/nonexistent/path/does-not-exist.mmdb"); err == nil {
		t.Fatal("Open(missing file) = nil error, want an error")
	}
}

// ---- end-to-end against a real .mmdb ------------------------------------

func TestReader_Lookup_EndToEnd(t *testing.T) {
	path := buildFixture(t, "Test-City")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	t.Run("hit/maxmind-schema/city-granularity", func(t *testing.T) {
		got, err := r.Lookup("192.0.2.5")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		want := Location{
			CountryCode: "US", Country: "United States", Region: "Test State", City: "Testville",
			RegionCode: "TS", Latitude: 40.5, Longitude: -89.25, AccuracyRadiusKm: 20,
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("hit/ipinfo-schema/country-granularity", func(t *testing.T) {
		got, err := r.Lookup("198.51.100.5")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		want := Location{CountryCode: "JP", Country: "Japan"}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("hit/ipv6/language-fallback", func(t *testing.T) {
		got, err := r.Lookup("2001:db8::1")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		// A country-level record: no location block, so no coordinates.
		if want := (Location{CountryCode: "DE", Country: "ドイツ"}); got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("miss/unmapped-range", func(t *testing.T) {
		got, err := r.Lookup("203.0.113.5")
		if err != nil || !got.Empty() {
			t.Fatalf("got %+v, %v; want empty, nil", got, err)
		}
	})

	t.Run("invalid-ip", func(t *testing.T) {
		got, err := r.Lookup("not-an-ip")
		if err != nil || !got.Empty() {
			t.Fatalf("got %+v, %v; want empty, nil", got, err)
		}
	})

	t.Run("private-ip-never-queried", func(t *testing.T) {
		got, err := r.Lookup("10.1.2.3")
		if err != nil || !got.Empty() {
			t.Fatalf("got %+v, %v; want empty, nil", got, err)
		}
	})

	t.Run("info", func(t *testing.T) {
		info := r.Info()
		if info.Type != "Test-City" {
			t.Fatalf("Type = %q, want Test-City", info.Type)
		}
		if info.Granularity != "city" {
			t.Fatalf("Granularity = %q, want city (DatabaseType contains \"City\")", info.Granularity)
		}
	})
}

func TestReader_Info_CountryGranularity(t *testing.T) {
	path := buildFixture(t, "Test-Country")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if got := r.Info().Granularity; got != "country" {
		t.Fatalf("Granularity = %q, want country", got)
	}
}

func TestLocation_Empty(t *testing.T) {
	if !(Location{}).Empty() {
		t.Fatal("zero Location.Empty() = false, want true")
	}
	if (Location{CountryCode: "US"}).Empty() {
		t.Fatal("Location with CountryCode set .Empty() = true, want false")
	}
	// Empty still asks only whether there is a named place to show; the
	// fields added later do not change its answer.
	if !(Location{RegionCode: "GD", Latitude: 23.125, Longitude: 113.25, AccuracyRadiusKm: 50}).Empty() {
		t.Fatal("Location with only a region code and coordinates .Empty() = false, want true")
	}
}

func TestReader_Lookup_Coordinates(t *testing.T) {
	r, err := Open(buildCoordinatesFixture(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	for _, c := range coordinateCases() {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.Lookup(c.ip)
			if err != nil {
				t.Fatalf("Lookup(%s): %v", c.ip, err)
			}
			if got != c.want {
				t.Fatalf("Lookup(%s) = %+v, want %+v", c.ip, got, c.want)
			}
		})
	}
}
