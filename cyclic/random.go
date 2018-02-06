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

// Initialize a new Random with min and max values
func NewRandom(min, max *Int) Random {
	fmax := NewInt(0)
	gen := Random{min, max, fmax.Sub(max, min), rand.Reader}
	return gen
}

// Generates a random Int between min and max
func (gen *Random) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.fmax.value)
	if err != nil {
		return nil
	}
	x.value = ran
	x = x.Add(x, gen.min)
	return x
}
