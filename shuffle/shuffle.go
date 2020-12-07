/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

// Package shuffle has a Fisher-Yates shuffle algorithm that we use for mixing
// the slots in our Permute phases.
package shuffle

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/csprng"
	"math"
	"math/bits"
)

// Legacy 64-bit shuffle implementation

// shuffleCore used in test to guarantee 100% coverage
func shuffleCore(shufflee *[]uint64, rng csprng.Source) {
	size := uint64(len(*shufflee))
	bufLen := uint64((bits.Len(uint(size-1)) + 7) >> 3)
	buf := make([]byte, bufLen)

	for curPos := uint64(0); curPos < size-1; curPos++ {
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled
		n, err := rng.Read(buf)
		if err != nil || n != len(buf) {
			jww.FATAL.Panicf("Could not generate random "+
				"number in Shuffle: %v", err.Error())
		}

		buf = append(make([]byte, 8-len(buf)), buf...)

		// Generate a number between curPos and size-1
		randPos := binary.BigEndian.Uint64(buf)
		randPos %= size - curPos
		randPos += curPos
		(*shufflee)[randPos], (*shufflee)[curPos] = (*shufflee)[curPos],
			(*shufflee)[randPos]
	}
}

// Shuffles a uint64 array using a Fisher-Yates shuffle
func Shuffle(shufflee *[]uint64) {
	// Skip empty lists or lists of only 1 element, they cannot be shuffled
	if len(*shufflee) <= 1 {
		return
	}
	shuffleCore(shufflee, csprng.NewSystemRNG())
}

// New, shiny 32-bit shuffle implementation

// shuffleCore32 used in test to guarantee 100% coverage
func shuffleCore32(shufflee *[]uint32, rng csprng.Source) {
	if uint64(len(*shufflee)) > math.MaxUint32 {
		jww.ERROR.Panic("Too many items in the shuffled batch")
	}
	size := uint32(len(*shufflee))
	// use 2 times the required bytes to reduce modulo bias to be more acceptable
	bufLen := 2 * (bits.Len(uint(size)) + 7) >> 3

	for curPos := uint32(0); curPos < size-1; curPos++ {
		buf := make([]byte, bufLen)
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled
		n, err := rng.Read(buf)
		if err != nil || n != len(buf) {
			jww.FATAL.Panicf("Could not generate random "+
				"number in Shuffle: %v", err.Error())
		}

		// Left pad buf to make it the right length for binary.BigEndian.Uint64
		buf = append(make([]byte, 8-len(buf)), buf...)

		// Generate a number between curPos and size-1
		// FIXME We should generate the numbers in a way that isn't biased
		// See XX-1036 for a ticket about the RNG redesign
		// https://privategrity.atlassian.net/browse/XX-1036
		randPos := binary.BigEndian.Uint64(buf)
		randPos %= uint64(size - curPos)
		randPos += uint64(curPos)
		(*shufflee)[randPos], (*shufflee)[curPos] = (*shufflee)[curPos],
			(*shufflee)[randPos]
	}
}

// Shuffle32 shuffles a uint32 array using a Fisher-Yates shuffle
func Shuffle32(shufflee *[]uint32) {
	// Skip empty lists or lists of only 1 element, they cannot be shuffled
	if len(*shufflee) <= 1 {
		return
	}
	shuffleCore32(shufflee, csprng.NewSystemRNG())
}
