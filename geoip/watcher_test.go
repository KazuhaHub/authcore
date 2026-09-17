package geoip

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWatcher_NilSafe(t *testing.T) {
	var w *Watcher
	w.SetPath("x")
	w.SetEnabled(false)
	w.Refresh()
	if got := w.Lookup("192.0.2.1"); !got.Empty() {
		t.Fatalf("nil Watcher.Lookup = %+v, want empty", got)
	}
	if st := w.Status(); st != (Status{}) {
		t.Fatalf("nil Watcher.Status = %+v, want zero value", st)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("nil Watcher.Close = %v, want nil", err)
	}
}

func TestWatcher_NoPathConfigured(t *testing.T) {
	w := NewWatcher()
	if got := w.Lookup("192.0.2.1"); !got.Empty() {
		t.Fatalf("Lookup with no path set = %+v, want empty", got)
	}
	st := w.Status()
	if st.Loaded {
		t.Fatalf("Status.Loaded = true with no path set")
	}
	if !st.Enabled {
		t.Fatal("Status.Enabled = false, want true (default)")
	}
}

func TestWatcher_MissingFile(t *testing.T) {
	w := NewWatcher(WithPath(filepath.Join(t.TempDir(), "does-not-exist.mmdb")))
	if got := w.Lookup("192.0.2.1"); !got.Empty() {
		t.Fatalf("Lookup against a missing file = %+v, want empty", got)
	}
	st := w.Status()
	if st.Loaded {
		t.Fatal("Status.Loaded = true for a missing file")
	}
	if st.Error == "" {
		t.Fatal("Status.Error = \"\", want the stat error surfaced")
	}
}

func TestWatcher_Disabled(t *testing.T) {
	path := buildFixture(t, "Test-Country")
	w := NewWatcher(WithPath(path), WithEnabled(false))
	if got := w.Lookup("192.0.2.1"); !got.Empty() {
		t.Fatalf("Lookup while disabled = %+v, want empty", got)
	}
	if st := w.Status(); st.Loaded {
		t.Fatal("Status.Loaded = true while disabled: file must not be opened")
	}

	w.SetEnabled(true)
	got := w.Lookup("192.0.2.5")
	if got.CountryCode != "US" {
		t.Fatalf("after SetEnabled(true), got %+v, want CountryCode=US", got)
	}
}

func TestWatcher_LookupAndStatus(t *testing.T) {
	path := buildFixture(t, "Test-City")
	w := NewWatcher(WithPath(path))
	defer w.Close()

	got := w.Lookup("198.51.100.5")
	want := Location{CountryCode: "JP", Country: "Japan"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	st := w.Status()
	if !st.Loaded {
		t.Fatal("Status.Loaded = false after a successful lookup")
	}
	if st.Info.Type != "Test-City" {
		t.Fatalf("Status.Info.Type = %q, want Test-City", st.Info.Type)
	}
	if st.Error != "" {
		t.Fatalf("Status.Error = %q, want empty", st.Error)
	}
}

func TestWatcher_HotReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.mmdb")

	// v1: US.
	v1 := buildFixture(t, "Test-City")
	copyFile(t, v1, path)

	w := NewWatcher(WithPath(path))
	defer w.Close()
	if got := w.Lookup("192.0.2.5"); got.CountryCode != "US" {
		t.Fatalf("v1: got %+v, want CountryCode=US", got)
	}

	// v2: same fixture builder, but content differs enough in size, and we
	// force the mtime forward — Watcher must notice and reopen rather than
	// keep serving the mmap'd v1 data.
	v2 := buildFixture(t, "Test-City-v2-with-a-longer-database-type-string")
	raw, err := os.ReadFile(v2)
	if err != nil {
		t.Fatalf("read v2: %v", err)
	}
	touchLarger(t, path, raw)

	got := w.Lookup("192.0.2.5")
	if got.CountryCode != "US" {
		t.Fatalf("v2: lookup should still resolve, got %+v", got)
	}
	if info := w.Status().Info; info.Type != "Test-City-v2-with-a-longer-database-type-string" {
		t.Fatalf("Status.Info.Type = %q after reload, want the v2 database type (reload did not happen)", info.Type)
	}
}

func TestWatcher_SetPathSwitchesDatabase(t *testing.T) {
	pathA := buildFixture(t, "Test-A") // has US at 192.0.2.0/24
	w := NewWatcher(WithPath(pathA))
	defer w.Close()
	if got := w.Lookup("192.0.2.5"); got.CountryCode != "US" {
		t.Fatalf("got %+v, want CountryCode=US from fixture A", got)
	}

	pathB := buildFixture(t, "Test-B")
	w.SetPath(pathB)
	if got := w.Lookup("198.51.100.5"); got.CountryCode != "JP" {
		t.Fatalf("got %+v, want CountryCode=JP from fixture B after SetPath", got)
	}
}

func TestWatcher_Close(t *testing.T) {
	path := buildFixture(t, "Test-City")
	w := NewWatcher(WithPath(path))
	_ = w.Lookup("192.0.2.5")
	if !w.Status().Loaded {
		t.Fatal("expected a loaded database before Close")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if w.Status().Loaded {
		t.Fatal("Status.Loaded = true after Close")
	}
	// A Lookup after Close must reopen the file rather than stay closed.
	if got := w.Lookup("192.0.2.5"); got.CountryCode != "US" {
		t.Fatalf("Lookup after Close = %+v, want it to reopen and resolve", got)
	}
}

// TestWatcher_ConcurrentLookupAndReload hammers Lookup from many goroutines
// while another goroutine keeps swapping the file and forcing Refresh/Close,
// under -race. This is the scenario the RLock-across-the-read design in
// Lookup exists for: reading a reader pointer and using it AFTER releasing
// the lock would let a concurrent Close() munmap it mid-read.
func TestWatcher_ConcurrentLookupAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.mmdb")
	copyFile(t, buildFixture(t, "Test-City"), path)

	w := NewWatcher(WithPath(path))
	defer w.Close()

	const readers = 8
	const iterations = 200
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					w.Lookup("192.0.2.5")
					w.Lookup("2001:db8::1")
				}
			}
		}()
	}

	for i := 0; i < iterations; i++ {
		raw, err := os.ReadFile(buildFixture(t, "Test-City"))
		if err != nil {
			t.Fatalf("build replacement fixture: %v", err)
		}
		touchLarger(t, path, raw)
		w.Refresh()
		if i%20 == 0 {
			_ = w.Close()
		}
	}
	close(stop)
	wg.Wait()
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
