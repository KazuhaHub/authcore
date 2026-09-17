package passkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestMemoryCredentialStore_SaveAndFind(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	handle := handleFor("alice")
	cred := webauthn.Credential{ID: []byte("cred-1")}

	if err := store.Save(ctx, StoredCredential{UserHandle: handle, Credential: cred}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.FindByID(ctx, []byte("cred-1"))
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if string(got.UserHandle) != string(handle) {
		t.Fatalf("UserHandle = %q, want %q", got.UserHandle, handle)
	}

	if _, err := store.FindByID(ctx, []byte("nope")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("FindByID(unknown) = %v, want ErrCredentialNotFound", err)
	}

	list, err := store.FindByUserHandle(ctx, handle)
	if err != nil || len(list) != 1 {
		t.Fatalf("FindByUserHandle = %v, %v; want one entry", list, err)
	}

	// A handle with nothing registered is empty, not an error.
	empty, err := store.FindByUserHandle(ctx, handleFor("nobody"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("FindByUserHandle(unknown handle) = %v, %v; want empty, nil", empty, err)
	}
}

func TestMemoryCredentialStore_SaveRejectsDuplicateID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	cred := StoredCredential{UserHandle: handleFor("alice"), Credential: webauthn.Credential{ID: []byte("dup")}}
	if err := store.Save(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, cred); err == nil {
		t.Fatal("saving a second credential with the same ID must fail")
	}
}

func TestMemoryCredentialStore_UpdateSignCount(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	handle := handleFor("alice")
	id := []byte("cred-1")
	if err := store.Save(ctx, StoredCredential{UserHandle: handle, Credential: webauthn.Credential{ID: id}}); err != nil {
		t.Fatal(err)
	}

	updated := webauthn.Credential{ID: id}
	updated.Authenticator.SignCount = 42
	if err := store.UpdateSignCount(ctx, id, updated, time.Now()); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	got, err := store.FindByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Credential.Authenticator.SignCount != 42 {
		t.Fatalf("SignCount = %d, want 42", got.Credential.Authenticator.SignCount)
	}
	// The user handle must survive the update -- UpdateSignCount only
	// replaces the credential, never reassigns ownership.
	if string(got.UserHandle) != string(handle) {
		t.Fatalf("UserHandle after update = %q, want %q", got.UserHandle, handle)
	}

	if err := store.UpdateSignCount(ctx, []byte("nope"), updated, time.Now()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("UpdateSignCount(unknown id) = %v, want ErrCredentialNotFound", err)
	}
}
