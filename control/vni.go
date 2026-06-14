package control

import (
	"errors"
	"sync"
	"time"
)

// MaxVNI is the top of the 24-bit Geneve VNI space. VNI 0 is reserved.
const MaxVNI = 1<<24 - 1

// ErrVNIExhausted is returned by Allocate when every VNI is live or
// quarantined. Unlike SPI exhaustion it is transient: releases and quarantine
// expiry free the space again.
var ErrVNIExhausted = errors.New("control: VNI space exhausted")

// VNIAllocator hands out VNIs from the 24-bit Geneve space with a quarantine
// window on release: a released VNI cannot be re-minted until the grace
// period elapses. This closes the slot-reuse race — return frames sealed
// under a dead network's still-unexpired SA must never demux to a successor
// holding the same VNI — so grace must cover the released SA's remaining
// lifetime. All methods are safe for concurrent use.
type VNIAllocator struct {
	mu          sync.Mutex
	grace       time.Duration
	now         func() time.Time
	max         uint32 // MaxVNI in production; lowered only by tests
	inUse       map[uint32]struct{}
	quarantined map[uint32]time.Time // VNI → earliest re-mint instant
	expiry      []qrelease           // FIFO of releases for pruning; ordered by `until`
	last        uint32               // last VNI handed out; scans resume past it
}

// qrelease records a release for the expiry sweep. Because grace is constant,
// appends are in non-decreasing `until` order, so pruneExpired can stop at the
// first still-quarantined entry.
type qrelease struct {
	vni   uint32
	until time.Time
}

// NewVNIAllocator returns an allocator whose released VNIs stay unmintable
// for grace.
func NewVNIAllocator(grace time.Duration) *VNIAllocator {
	return &VNIAllocator{
		grace:       grace,
		now:         time.Now,
		max:         MaxVNI,
		inUse:       make(map[uint32]struct{}),
		quarantined: make(map[uint32]time.Time),
	}
}

// Allocate returns a free VNI in [1, MaxVNI]. It scans forward from the last
// allocation (wrapping), skipping live and quarantined VNIs, so beyond the
// hard quarantine a VNI is also not reused until the rest of the space has
// cycled.
func (a *VNIAllocator) Allocate() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.pruneExpired(now)
	if uint32(len(a.inUse)) >= a.max {
		return 0, ErrVNIExhausted // every VNI is live; the ring scan would find nothing.
	}
	for i := uint32(1); i <= a.max; i++ {
		cand := (a.last+i-1)%a.max + 1
		if _, live := a.inUse[cand]; live {
			continue
		}
		if until, q := a.quarantined[cand]; q {
			if now.Before(until) {
				continue
			}
			delete(a.quarantined, cand)
		}
		a.inUse[cand] = struct{}{}
		a.last = cand
		return cand, nil
	}
	return 0, ErrVNIExhausted
}

// Release moves a live VNI into quarantine, (re)starting its grace window.
// Releasing an unknown VNI still quarantines it (idempotent under the
// crash-cleanup/explicit-release overlap, and conservative: a double release
// extends the window rather than shortening it).
func (a *VNIAllocator) Release(vni uint32) {
	if vni == 0 || vni > a.max {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.pruneExpired(now)
	delete(a.inUse, vni)
	until := now.Add(a.grace)
	if cur, ok := a.quarantined[vni]; !ok || until.After(cur) {
		a.quarantined[vni] = until
	}
	a.expiry = append(a.expiry, qrelease{vni: vni, until: until})
}

// pruneExpired drops quarantine entries whose grace has elapsed, bounding the
// quarantined map under sustained low-occupancy churn — where Allocate's
// forward scan would otherwise never revisit a released VNI to lazily expire it,
// so the map would grow without bound. The expiry queue is FIFO and (grace
// being constant) ordered by deadline, so the sweep stops at the first
// still-quarantined entry. The caller must hold a.mu.
func (a *VNIAllocator) pruneExpired(now time.Time) {
	i := 0
	for i < len(a.expiry) && !now.Before(a.expiry[i].until) {
		e := a.expiry[i]
		// Only delete when the map's authoritative deadline matches this entry
		// (no later, extending release superseded it) and has elapsed; an
		// extended release leaves a newer queue entry that expires it instead.
		if until, ok := a.quarantined[e.vni]; ok && !until.After(e.until) && !now.Before(until) {
			delete(a.quarantined, e.vni)
		}
		i++
	}
	if i > 0 {
		a.expiry = a.expiry[i:]
	}
}

// Live reports the number of currently allocated VNIs.
func (a *VNIAllocator) Live() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.inUse)
}
