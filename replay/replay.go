/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

import "sync"

const (
	// RekeyAfterMessages is the maximum number of messages that can be sent before rekeying.
	RekeyAfterMessages = (1 << 60)
	// RejectAfterMessages is the maximum number of messages that can be accepted before rejecting further messages.
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1
)

type block uint64

const (
	blockBitLog = 6                // 1<<6 == 64 bits
	blockBits   = 1 << blockBitLog // must be power of 2
	ringBlocks  = 1 << 7           // must be power of 2
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
)

// Filter rejects replayed messages by checking if message counter value is
// within a sliding window of previously received messages.
// The zero value for Filter is an empty, ready-to-use, thread-safe filter.
type Filter struct {
	mu   sync.Mutex
	last uint64
	ring [ringBlocks]block
}

// Reset resets the filter to empty state.
func (f *Filter) Reset() {
	f.mu.Lock()
	f.last = 0
	f.ring[0] = 0
	// Optionally clear the rest to be thorough:
	for i := 1; i < ringBlocks; i++ {
		f.ring[i] = 0
	}
	f.mu.Unlock()
}

// ValidateCounter checks if the counter should be accepted.
// Overlimit counters (>= limit) are always rejected.
func (f *Filter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	indexBlock := counter >> blockBitLog
	if counter > f.last { // move window forward
		current := f.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks // cap diff to clear the whole ring
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = counter
	} else if f.last-counter > windowSize { // behind current window
		return false
	}

	// check and set bit
	idx := indexBlock & blockMask
	indexBit := counter & bitMask
	old := f.ring[idx]
	new := old | 1<<indexBit
	f.ring[idx] = new
	return old != new
}
