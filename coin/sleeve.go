package coin

// Contains everything a wallet knows about a compound coin
type Sleeve struct {
	seed     *Seed
	compound *Compound
	value    uint64
}

// Builds a new coin inside of a coinsleeve
func NewSleeve(value uint64) (Sleeve, error) {

	seed, err := NewSeed(value)

	if err != nil {
		return Sleeve{}, err
	}

	compound := seed.ComputeCompound()

	return Sleeve{&seed, &compound, value}, nil
}

// Constructs a Sleeve from a seed pointer and a compound pointer.
func ConstructSleeve(s *Seed, c *Compound) Sleeve {
	var value uint64

	if s != nil {
		seed := s.Copy()
		s = &seed
		value = s.Value()
	}

	if c != nil {
		compound := c.Copy()
		c = &compound
		value = c.Value()
	}

	return Sleeve{s, c, value}
}

// Tells the user if they own the coin
func (cs Sleeve) Mine() bool {
	return cs.seed != nil
}

//Returns a copy of the seed
func (cs Sleeve) Seed() Seed {
	return cs.seed.Copy()
}

//Returns a copy of the seed pointer
func (cs Sleeve) Compound() Compound {
	return cs.compound.Copy()
}

//Returns a copy of the value
func (cs Sleeve) Value() uint64 {
	return cs.value
}
