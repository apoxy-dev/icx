package psp

import "testing"

func TestRolePeer(t *testing.T) {
	if Initiator.Peer() != Responder || Responder.Peer() != Initiator {
		t.Fatalf("Peer() must swap roles: got %v/%v", Initiator.Peer(), Responder.Peer())
	}
}

func TestEpochSPIs(t *testing.T) {
	cases := []struct {
		name    string
		role    Role
		epoch   uint32
		wantErr bool
	}{
		{"epoch0_rejected", Initiator, 0, true},
		{"epoch_over_max_rejected", Initiator, SPICounterMax + 1, true},
		{"epoch1_initiator", Initiator, 1, false},
		{"epoch1_responder", Responder, 1, false},
		{"epoch_max", Responder, SPICounterMax, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rx, tx, err := EpochSPIs(c.role, c.epoch)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got rx=%#x tx=%#x", rx, tx)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rx == tx {
				t.Fatalf("rx and tx SPIs must differ, both %#x", rx)
			}
			if RoleOf(rx) != c.role || RoleOf(tx) != c.role.Peer() {
				t.Fatalf("role bits wrong: rx=%#x tx=%#x for role %v", rx, tx, c.role)
			}
			if MasterKeyIndex(rx) != 0 || MasterKeyIndex(tx) != 0 {
				t.Fatalf("EpochSPIs must use master-key index 0: rx=%#x tx=%#x", rx, tx)
			}
			// The two peers of a connection must see mirrored pairs.
			prx, ptx, err := EpochSPIs(c.role.Peer(), c.epoch)
			if err != nil {
				t.Fatal(err)
			}
			if prx != tx || ptx != rx {
				t.Fatalf("peer pair not mirrored: local rx/tx=%#x/%#x, peer rx/tx=%#x/%#x", rx, tx, prx, ptx)
			}
		})
	}
}
