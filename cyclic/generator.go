package cyclic

import (
	"crypto/rand"
	"io"
)

type Gen struct {
	min    *Int
	max    *Int
	fmax   *Int
	reader io.Reader
}

// Initialize a new Gen with min and max values
func NewGen(min, max *Int) Gen {
	fmax := NewInt(0)
	gen := Gen{min, max, fmax.Sub(max, min), rand.Reader}
	return gen
}

// Generates a random Int between min and max
func (gen Gen) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.max.value)
	if err != nil {
		return nil
	}
	x.value = ran
	x = x.Add(x, gen.min)
	return x
}
