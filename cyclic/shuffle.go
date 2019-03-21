////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"gitlab.com/elixxir/crypto/large"
	"math"
)

// Shuffles a uint64 array using a Fisher-Yates shuffle
func Shuffle(shufflee *[]uint64) {
	// Skip empty lists or lists of only 1 element, they cannot be shuffled
	if len(*shufflee) <= 1 {
		return
	}

	g := NewRandom(large.NewInt(0), large.NewInt(int64(len(*shufflee))-1))

	x := large.NewIntFromUInt(math.MaxInt64)

	for curPos := int64(0); curPos < int64(len(*shufflee))-1; curPos++ {
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled
		g.SetMinFromInt64(curPos)
		randPos := g.Rand(x).Int64()
		(*shufflee)[randPos], (*shufflee)[curPos] = (*shufflee)[curPos],
			(*shufflee)[randPos]
	}
}
