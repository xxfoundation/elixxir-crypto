////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"math/bits"
	"encoding/binary"
)

// Used in test to guarantee 100% coverage
func shuffleCore(shufflee *[]uint64, rng csprng.Source) {
	size := uint64(len(*shufflee))
	bufLen := uint64((bits.Len(uint(size-1))+7)>>3)
	buf := make([]byte, bufLen)

	for curPos := uint64(0); curPos < size-1; curPos++ {
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled
		n, err := rng.Read(buf)
		if err != nil || n != len(buf) {
			jww.FATAL.Panicf("Could not generate random "+
				"number in Shuffle: %v", err.Error())
		}

		buf = append(make([]byte,8-len(buf)),buf...)

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
