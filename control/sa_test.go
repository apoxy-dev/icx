package control

import (
	"bytes"
	"testing"
)

func TestDeriveMasterKeysDeterministic(t *testing.T) {
	root := bytes.Repeat([]byte{0xA5}, RootSecretLen)
	a, err := DeriveMasterKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveMasterKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	if a.keys != b.keys {
		t.Fatal("master keys not deterministic for the same root secret")
	}
	if a.keys[0] == a.keys[1] {
		t.Fatal("the two master keys must differ")
	}
}

func TestDeriveMasterKeysSessionUnique(t *testing.T) {
	a, _ := DeriveMasterKeys(bytes.Repeat([]byte{0x01}, RootSecretLen))
	b, _ := DeriveMasterKeys(bytes.Repeat([]byte{0x02}, RootSecretLen))
	if a.keys == b.keys {
		t.Fatal("different root secrets must yield different master keys (per-session FS)")
	}
}

func TestDeriveMasterKeysRejectsShortRoot(t *testing.T) {
	if _, err := DeriveMasterKeys(make([]byte, RootSecretLen-1)); err == nil {
		t.Fatal("expected error for short root secret")
	}
}

func TestDeriveSAMatchesKDFAndSelectsMasterKey(t *testing.T) {
	mk, _ := DeriveMasterKeys(bytes.Repeat([]byte{0x5a}, RootSecretLen))

	// MSB clear -> master key 0; MSB set -> master key 1.
	spi0, _ := MakeSPI(0, Initiator, 7)
	spi1, _ := MakeSPI(1, Initiator, 7)

	sa0, err := mk.DeriveSA(spi0, AESGCM128)
	if err != nil {
		t.Fatal(err)
	}
	want0, _ := DeriveSAKey(mk.keys[0][:], spi0, AESGCM128)
	if !bytes.Equal(sa0.Key, want0) {
		t.Fatal("DeriveSA(MSB=0) did not use master key 0")
	}

	sa1, err := mk.DeriveSA(spi1, AESGCM128)
	if err != nil {
		t.Fatal(err)
	}
	want1, _ := DeriveSAKey(mk.keys[1][:], spi1, AESGCM128)
	if !bytes.Equal(sa1.Key, want1) {
		t.Fatal("DeriveSA(MSB=1) did not use master key 1")
	}
}

// TestDirectionsNeverCollide is the txKey != rxKey guarantee: the two peers
// allocate RX SPIs independently, but the role bit keeps them in disjoint
// subspaces, so the same counter yields different SPIs and thus different keys.
func TestDirectionsNeverCollide(t *testing.T) {
	mk, _ := DeriveMasterKeys(bytes.Repeat([]byte{0x33}, RootSecretLen))
	initAlloc := NewSPIAllocator(Initiator)
	respAlloc := NewSPIAllocator(Responder)

	seen := map[uint32]bool{}
	for i := 0; i < 1000; i++ {
		is, err := initAlloc.Allocate(0)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := respAlloc.Allocate(0)
		if err != nil {
			t.Fatal(err)
		}
		if is == rs {
			t.Fatalf("initiator and responder allocated the same SPI %#x", is)
		}
		if seen[is] || seen[rs] {
			t.Fatalf("SPI reuse detected at i=%d", i)
		}
		seen[is], seen[rs] = true, true

		txSA, _ := mk.DeriveSA(is, AESGCM128)
		rxSA, _ := mk.DeriveSA(rs, AESGCM128)
		if bytes.Equal(txSA.Key, rxSA.Key) {
			t.Fatal("tx and rx SA keys collided")
		}
	}
}

func TestMakeSPIValidation(t *testing.T) {
	if _, err := MakeSPI(0, Initiator, 0); err == nil {
		t.Fatal("counter 0 must be rejected")
	}
	if _, err := MakeSPI(2, Initiator, 1); err == nil {
		t.Fatal("master key index 2 must be rejected")
	}
	if _, err := MakeSPI(0, Initiator, spiCounterMask+1); err == nil {
		t.Fatal("counter overflow must be rejected")
	}
}

func TestDeriveSARejectsReservedSPI(t *testing.T) {
	mk, _ := DeriveMasterKeys(bytes.Repeat([]byte{0x01}, RootSecretLen))
	// SPI whose low 31 bits are zero (only the master-key bit set) is reserved.
	if _, err := mk.DeriveSA(uint32(1)<<31, AESGCM128); err == nil {
		t.Fatal("expected error for reserved SPI (zero low 31 bits)")
	}
}
