/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

import (
	"sync/atomic"
)

const (
	// RejectAfterMessages is the maximum number of messages that can be accepted before rejecting further messages.
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1
)

type block = atomic.Uint64

const (
	blockBitLog = 6                // 1<<6 == 64 bits
	blockBits   = 1 << blockBitLog // must be power of 2
	ringBlocks  = 1 << 7           // must be power of 2
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
)

type Filter struct {
	last atomic.Uint64
	ring [ringBlocks]block
}

func (f *Filter) Reset() {
	f.last.Store(0)
	f.ring[0].Store(0)
}

// ValidateCounter checks if the counter should be accepted.
func (f *Filter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}

	indexBlock := counter >> blockBitLog
	last := f.last.Load()

	if counter > last {
		current := last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask].Store(0)
		}
		f.last.Store(counter)
	} else if last-counter > windowSize {
		return false
	}

	indexBlock &= blockMask
	indexBit := counter & bitMask

	ptr := &f.ring[indexBlock]
	mask := uint64(1) << indexBit

	for {
		old := ptr.Load()
		if old&mask != 0 {
			return false
		}
		if ptr.CompareAndSwap(old, old|mask) {
			return true
		}
	}
}
