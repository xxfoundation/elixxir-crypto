package cyclic

import "crypto/rand"

type Gen struct {
	min *Int
	max *Int
}

// Initialize a new Gen with min and max values
func NewGen(min, max *Int) Gen {
	gen := Gen{min, max}
	return gen
}

// Generates a random Int between min and max, performance degrades
// as min approaches max
func (gen Gen) Rand(x *Int) *Int {
	ran, err := rand.Int(rand.Reader, gen.max.value)
	if err != nil {
		return nil
	}
	x.value = ran

	for x.Cmp(gen.min) < 0 {
		ran, err := rand.Int(rand.Reader, gen.max.value)
		if err != nil {
			return nil
		}
		x.value = ran
	}
	return x
}
