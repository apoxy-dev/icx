package icx

import (
	"fmt"
	"time"
)

// InstallKeysForTest installs RX/TX ciphers under a single shared epoch (rxSPI ==
// txSPI == epoch) without the production monotonicity and distinct-key guards enforced
// by UpdateVirtualNetworkSAs.
//
// It exists only for in-process loopback tests that encrypt and decrypt on a
// single handler with one shared key (the byte-equivalence, round-trip, fuzz and
// benchmark harnesses). Real peers always derive distinct per-direction keys and
// strictly increasing per-direction SPIs, so the guarded UpdateVirtualNetworkSAs
// deliberately rejects that shape — hence this unguarded test seam. The file name ends
// in _test.go, so it is compiled only under `go test` and never ships in the
// production binary or public API.
func (h *Handler) InstallKeysForTest(vni uint, epoch uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	return h.installKeys(value.(*VirtualNetwork), epoch, epoch, rxKey, txKey, expiresAt)
}

// TxCounterForTest returns the active SA's current TX nonce counter for the VNI (and
// whether one is installed). It lets a test assert the per-epoch fresh-counter
// invariant — each new epoch install resets the counter to zero — which is what keeps
// the AES-GCM nonce (epoch‖counter) unique as epochs climb across rekeys/restarts.
func (h *Handler) TxCounterForTest(vni uint) (uint64, bool) {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return 0, false
	}
	tc := value.(*VirtualNetwork).txCipher.Load()
	if tc == nil {
		return 0, false
	}
	return tc.counter.Load(), true
}
