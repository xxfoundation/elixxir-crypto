package cyclic

import (
	"crypto/rand"
	"io"
)

type Random struct {
	min    *Int
	max    *Int
	fmax   *Int
	reader io.Reader
}

func (r *Random) recalculateRange() {
	r.fmax.Sub(r.max, r.min)
}

func (r *Random) SetMin(newMin *Int) {
	r.min.Set(newMin)
	r.recalculateRange()
}

func (r *Random) SetMinFromInt64(newMin int64) {
	r.min.SetInt64(newMin)
	r.recalculateRange()
}

func (r *Random) SetMax(newMax *Int) {
	r.max.Set(newMax)
	r.recalculateRange()
}

func (r *Random) SetMaxFromInt64(newMax int64) {
	r.max.SetInt64(newMax)
	r.recalculateRange()
}

// Initialize a new Random with min and max values
func NewRandom(min, max *Int) Random {
	fmax := NewInt(0)
	gen := Random{min, max, fmax.Sub(max, min), rand.Reader}
	return gen
}

// Generates a random Int x, min <= x < max
func (gen *Random) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.fmax.value)
	if err != nil {
		panic(err.Error())
	}
	x.value = ran
	x = x.Add(x, gen.min)
	return x
}
