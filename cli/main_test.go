//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apoxy-dev/icx/control"
)

// APO-658 (S15): loadIdentity must refuse an identity private key that group or
// others can access, the way OpenSSH/WireGuard guard private keys, and accept one
// locked down to 0600 (what `icx genkey` writes).
func TestLoadIdentityRejectsInsecurePerms(t *testing.T) {
	id, err := control.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := id.MarshalPrivatePEM()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.pem")

	// Group/world-readable: must be rejected before the key is even parsed.
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(path); err == nil {
		t.Fatal("loadIdentity accepted a 0644 identity key; expected a permissions error")
	}

	// Tightened to 0600: must be accepted.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(path); err != nil {
		t.Fatalf("loadIdentity rejected a 0600 identity key: %v", err)
	}

	// A missing file surfaces a stat error, not a panic.
	if _, err := loadIdentity(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Fatal("loadIdentity accepted a missing key path")
	}
}
