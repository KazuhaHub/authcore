package geoip

import (
	"os"
	"sync"
	"time"
)

// Watcher serves lookups against a single .mmdb file, hot-reloading it when
// the file on disk changes (a new build, a fresh download, an operator
// dropping in a replacement) without a caller restart.
//
// It deliberately does not scan a directory or choose between several
// candidate files — "which database is active" is a policy decision that
// belongs to the caller (a setting, an admin's pick, "newest wins", ...).
// Watcher only answers "reload the one file I was told about, when it
// changes." Point it at a different file at any time with SetPath.
//
// A nil *Watcher is safe to call every method on: it behaves like a disabled
// Watcher with no database loaded.
//
// The watched file MUST be replaced by an atomic rename (write the new
// content to a temp file beside it, then os.Rename over the watched path),
// never by truncating and rewriting the same path in place. Watcher's
// internal lock only protects its own reader pointer, not the bytes
// underneath an already memory-mapped file: an in-place rewrite can hand a
// concurrent, in-flight Lookup a SIGBUS. A rename swaps the directory entry
// to a new inode, so an in-flight Lookup keeps reading the old (now unlinked
// but still open and unmodified) inode safely to completion. Both PSP's and
// RP's own database updaters already replace files this way.
type Watcher struct {
	enabled bool // immutable after construction except via SetEnabled

	mu      sync.RWMutex
	path    string
	reader  *Reader
	modTime time.Time
	size    int64
	openErr error
}

// Option configures a Watcher.
type Option func(*Watcher)

// WithPath sets the initial database file to watch. Equivalent to calling
// SetPath right after NewWatcher.
func WithPath(path string) Option {
	return func(w *Watcher) { w.path = path }
}

// WithEnabled sets whether the Watcher resolves addresses at all. A disabled
// Watcher never opens its file and Lookup always returns an empty Location —
// this lets a caller wire in an on/off setting without branching around every
// call site. Enabled by default.
func WithEnabled(enabled bool) Option {
	return func(w *Watcher) { w.enabled = enabled }
}

// NewWatcher creates a Watcher. It does not open the database file yet — the
// first Lookup or Refresh does, so a Watcher can be constructed before its
// target file exists.
func NewWatcher(opts ...Option) *Watcher {
	w := &Watcher{enabled: true}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// SetPath changes which file the Watcher serves. Takes effect on the next
// Lookup or Refresh; the previously open database (if any) stays in use until
// then, so callers see no gap.
func (w *Watcher) SetPath(path string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.path = path
	w.mu.Unlock()
}

// SetEnabled turns resolution on or off at runtime.
func (w *Watcher) SetEnabled(enabled bool) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.enabled = enabled
	w.mu.Unlock()
}

// Lookup resolves one address against the current database, reloading it
// first if the underlying file has changed. Like Reader.Lookup, an
// unresolvable, unmapped, or (here) disabled/unloaded case is a zero Location
// with no error — this method never fails, so a caller resolving many
// addresses never needs per-address error handling. Use Status to observe
// whether the database is actually loaded.
//
// The reload check and the actual database read happen under the same read
// lock: maxminddb.Reader.Close() munmaps the file, so a Lookup that captured
// a reader pointer and then read it AFTER releasing the lock could race a
// concurrent reload/Close and dereference already-unmapped memory — a SIGSEGV
// nothing in Go can recover from. Holding RLock across the read (not just
// across the pointer fetch) is what rules that out; only the rare reload
// briefly blocks a concurrent Lookup, never the other way around.
func (w *Watcher) Lookup(ip string) Location {
	if w == nil {
		return Location{}
	}
	w.refresh()
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.reader == nil {
		return Location{}
	}
	loc, _ := w.reader.Lookup(ip)
	return loc
}

// Refresh makes sure the watched file has been (re)opened if it changed,
// without performing a lookup. Callers that only want to force a reload after
// replacing the file (rather than waiting for the next Lookup) can call this.
func (w *Watcher) Refresh() {
	if w == nil {
		return
	}
	w.refresh()
}

// Status reports the Watcher's current state, for a caller's own admin or
// health view.
type Status struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	Loaded  bool   `json:"loaded"`
	Info    DBInfo `json:"info"`
	Error   string `json:"error,omitempty"` // set when Path is non-empty but failed to open
}

// Status returns a snapshot of the Watcher's state without forcing a reload
// check (it reports whatever is currently loaded).
func (w *Watcher) Status() Status {
	if w == nil {
		return Status{}
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	st := Status{Enabled: w.enabled, Path: w.path, Loaded: w.reader != nil}
	if w.reader != nil {
		st.Info = w.reader.Info()
	}
	if w.openErr != nil {
		st.Error = w.openErr.Error()
	}
	return st
}

// Close releases the currently loaded database, if any. The watched path is
// kept: a subsequent Lookup reopens it rather than staying dark, since Close
// is meant for releasing resources (e.g. at shutdown), not for disabling the
// Watcher — use SetEnabled(false) for that.
func (w *Watcher) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader == nil {
		return nil
	}
	err := w.reader.Close()
	w.reader, w.modTime, w.size = nil, time.Time{}, 0
	return err
}

// refresh (re)opens the watched file if it is disabled, unset, missing, or
// has changed since the last open, leaving the result in w.reader. It does
// NOT return the reader: callers must fetch w.reader under their own RLock
// (held across their actual use of it) rather than use a pointer handed back
// here, or a concurrent reload/Close racing after this returns could munmap
// the very reader they are about to dereference. See Lookup's doc comment.
//
// mtime AND size are compared (not mtime alone): a file rewritten within the
// same whole-second timestamp — which a scripted download can do — changes
// size far more reliably than it changes a whole-second stamp.
func (w *Watcher) refresh() {
	w.mu.RLock()
	enabled, path := w.enabled, w.path
	w.mu.RUnlock()
	if !enabled || path == "" {
		return
	}

	fi, statErr := os.Stat(path)
	var mod time.Time
	var size int64
	if statErr == nil {
		mod, size = fi.ModTime(), fi.Size()
	}

	w.mu.RLock()
	if w.reader != nil && w.path == path && w.modTime.Equal(mod) && w.size == size {
		w.mu.RUnlock()
		return
	}
	w.mu.RUnlock()

	w.mu.Lock()
	defer w.mu.Unlock()
	// Re-check under the write lock: two Lookups can race into here and only
	// one should actually reopen the file.
	if w.reader != nil && w.path == path && w.modTime.Equal(mod) && w.size == size {
		return
	}
	if statErr != nil {
		// File missing or unreadable: drop any stale reader rather than keep
		// serving a database that is no longer the one on disk.
		if w.reader != nil {
			_ = w.reader.Close()
		}
		w.reader, w.path, w.modTime, w.size, w.openErr = nil, path, time.Time{}, 0, statErr
		return
	}
	nr, err := Open(path)
	if err != nil {
		// Leave nil so Lookup answers "unknown" rather than propagating a
		// failure — a half-written or corrupt file is the common cause and it
		// fixes itself on the next successful write. Status surfaces err for
		// an operator who wants to know why.
		if w.reader != nil {
			_ = w.reader.Close()
		}
		w.reader, w.path, w.modTime, w.size, w.openErr = nil, path, mod, size, err
		return
	}
	if w.reader != nil {
		_ = w.reader.Close()
	}
	w.reader, w.path, w.modTime, w.size, w.openErr = nr, path, mod, size, nil
}
