////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"math"
	"math/bits"
	"encoding/binary"
)

// Used in test to guarantee 100% coverage
func shuffleCore(shufflee *[]uint32, rng csprng.Source) {
	if len(*shufflee) > math.MaxUint32 {
		jww.ERROR.Panic("Too many items in the shuffled batch")
	}
	size := uint32(len(*shufflee))
	bufLen := uint32((bits.Len(uint(size))+7)>>3)
	buf := make([]byte, bufLen)

	for curPos := uint32(0); curPos < size-1; curPos++ {
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled
		n, err := rng.Read(buf)
		if err != nil || n != len(buf) {
			jww.FATAL.Panicf("Could not generate random "+
				"number in Shuffle: %v", err.Error())
		}

		buf = append(make([]byte,4-len(buf)),buf...)

		// Generate a number between curPos and size-1
		randPos := binary.BigEndian.Uint32(buf)
		randPos %= size - curPos
		randPos += curPos
		println(randPos)
		(*shufflee)[randPos], (*shufflee)[curPos] = (*shufflee)[curPos],
			(*shufflee)[randPos]
	}
}

// Shuffles a uint32 array using a Fisher-Yates shuffle
func Shuffle(shufflee *[]uint32) {
	// Skip empty lists or lists of only 1 element, they cannot be shuffled
	if len(*shufflee) <= 1 {
		return
	}
	shuffleCore(shufflee, csprng.NewSystemRNG())
}
