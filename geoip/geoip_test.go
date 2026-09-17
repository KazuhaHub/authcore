package geoip

import "testing"

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
		want := Location{CountryCode: "US", Country: "United States", Region: "Test State", City: "Testville"}
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
		if got.CountryCode != "DE" || got.Country != "ドイツ" {
			t.Fatalf("got %+v, want DE/ドイツ", got)
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
}
