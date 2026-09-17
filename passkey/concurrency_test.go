package passkey

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentRegistrations proves many registration ceremonies begun
// concurrently against one Service, for distinct handles, do not cross:
// each ceremony's Finish is checked cryptographically against its OWN
// challenge (bound into the signed clientDataJSON), so any session mixup
// inside the shared SessionStore would show up as a verification failure
// here, not just a wrong-looking result.
//
// Goroutines report failures over a channel rather than calling t.Fatal
// directly -- the testing package requires Fatal/FailNow to run on the
// test's own goroutine.
func TestConcurrentRegistrations(t *testing.T) {
	ctx := context.Background()
	svc, creds := newTestService(t, nil)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := handleFor(fmt.Sprintf("actor-%02d", i))
			dev := newDevice(testRPID, testOrigin, handle)
			cred, err := registerDeviceE(ctx, svc, dev, handle, "K")
			if err != nil {
				errs <- err.Error()
				return
			}
			stored, err := creds.FindByID(ctx, cred.ID)
			if err != nil {
				errs <- err.Error()
				return
			}
			if string(stored.UserHandle) != string(handle) {
				errs <- fmt.Sprintf("actor %d: registered credential resolved to the wrong handle", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestConcurrentLogins mirrors TestConcurrentRegistrations for the
// allow-listed login ceremony, against credentials registered up front.
func TestConcurrentLogins(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, nil)

	const n = 50
	type actor struct {
		handle []byte
		dev    *device
	}
	actors := make([]actor, n)
	for i := range actors {
		h := handleFor(fmt.Sprintf("actor-%02d", i))
		d := newDevice(testRPID, testOrigin, h)
		registerDevice(t, ctx, svc, d, h, "K")
		actors[i] = actor{handle: h, dev: d}
	}

	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i, a := range actors {
		wg.Add(1)
		go func(i int, a actor) {
			defer wg.Done()
			sessionID, body, err := signAssertionAllowListedE(ctx, svc, a.dev, a.handle)
			if err != nil {
				errs <- err.Error()
				return
			}
			result, err := svc.FinishLogin(ctx, a.handle, sessionID, jsonRequest(body))
			if err != nil {
				errs <- err.Error()
				return
			}
			if string(result.UserHandle) != string(a.handle) {
				errs <- fmt.Sprintf("actor %d: login resolved to the wrong handle", i)
			}
		}(i, a)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
