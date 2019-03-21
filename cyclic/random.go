////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"crypto/rand"
	"gitlab.com/elixxir/crypto/large"
	"io"
)

type Random struct {
	min    large.Int
	max    large.Int
	fmax   large.Int
	one    large.Int
	reader io.Reader
}

// The random range is inclusive of both the minimum and maximum boundaries of
// the random range
func (r *Random) recalculateRange() {
	r.fmax.Sub(r.max, r.min)
	r.fmax.Add(r.fmax, r.one)
}

// SetMin sets Minimum value for the lower boundary of the random range
func (r *Random) SetMin(newMin large.Int) {
	r.min.Set(newMin)
	r.recalculateRange()
}

// SetMinFromInt64 sets Min value for the lower boundary of the random range (int 64 version)
func (r *Random) SetMinFromInt64(newMin int64) {
	r.min.SetInt64(newMin)
	r.recalculateRange()
}

// SetMax sets Max value for the upper boundary of the random range
func (r *Random) SetMax(newMax large.Int) {
	r.max.Set(newMax)
	r.recalculateRange()
}

// SetMaxFromInt64 sets Max val for the upper boundary of the random range (int 64 version)
func (r *Random) SetMaxFromInt64(newMax int64) {
	r.max.SetInt64(newMax)
	r.recalculateRange()
}

// NewRandom initializes a new Random with min and max values
func NewRandom(min, max large.Int) Random {
	fmax := large.NewInt(0)
	gen := Random{min, max, fmax.Sub(max, min), large.NewInt(1), rand.Reader}
	return gen
}

// Rand generates a random Int x, min <= x < max
func (gen *Random) Rand(x large.Int) large.Int {
	ran, err := rand.Int(gen.reader, gen.fmax.BigInt())
	if err != nil {
		panic(err.Error())
	}
	x.SetBigInt(ran)
	x = x.Add(x, gen.min)
	return x
}
