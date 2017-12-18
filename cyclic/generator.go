package cyclic

import (
	"crypto/rand"
	"io"
)

type Gen struct {
	min    *Int
	max    *Int
	reader io.Reader
}

// Initialize a new Gen with min and max values
func NewGen(min, max *Int) Gen {
	gen := Gen{min, max, rand.Reader}
	return gen
}

// Generates a random Int between min and max, performance degrades
// as min approaches max
func (gen Gen) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.max.value)
	if err != nil {
		return nil
	}
	x.value = ran

	for x.Cmp(gen.min) < 0 {
		ran, err := rand.Int(gen.reader, gen.max.value)
		if err != nil {
			return nil
		}
		x.value = ran
	}
	return x
}
