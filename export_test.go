package icx

import (
	"fmt"
	"time"
)

// InstallKeysForTest installs RX/TX ciphers under epoch without the production
// monotonicity and distinct-key guards enforced by UpdateVirtualNetworkKeys.
//
// It exists only for in-process loopback tests that encrypt and decrypt on a
// single handler with one shared key (the byte-equivalence, round-trip, fuzz and
// benchmark harnesses). Real peers always derive distinct per-direction keys and
// strictly increasing SPIs, so the guarded UpdateVirtualNetworkKeys deliberately
// rejects that shape — hence this unguarded test seam. The file name ends in
// _test.go, so it is compiled only under `go test` and never ships in the
// production binary or public API.
func (h *Handler) InstallKeysForTest(vni uint, epoch uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	return h.installKeys(value.(*VirtualNetwork), epoch, rxKey, txKey, expiresAt)
}
