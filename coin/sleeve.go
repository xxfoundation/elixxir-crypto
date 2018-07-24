package coin

import (
	"encoding/binary"
)

const GobSeedStart = uint64(0)
const GobSeedEnd = GobSeedStart + BaseFrameLen

const GobCompoundStart = GobSeedEnd
const GobCompoundEnd = GobCompoundStart + BaseFrameLen

const GobValueStart = GobCompoundEnd
const GobValueLen = uint64(8)
const GobValueEnd = GobValueStart + GobValueLen

const GobLen = 2*BaseFrameLen + GobValueLen

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
func (cs Sleeve) IsMine() bool {
	return cs.seed != nil
}

// Returns a pointer to a copy of the seed
// Returns nil if there is no seed
func (cs Sleeve) Seed() *Seed {
	if cs.seed == nil {
		return nil
	}

	seedCopy := cs.seed.Copy()

	return &seedCopy
}

// Returns a pointer to a copy of the compound
// Returns nil if there is no compound
func (cs Sleeve) Compound() *Compound {
	if cs.compound == nil {
		return nil
	}
	compoundCopy := cs.compound.Copy()

	return &compoundCopy
}

//Returns a copy of the value
func (cs Sleeve) Value() uint64 {
	return cs.value
}

//Returns if the sleeve is nill
func (cs Sleeve) IsNil() bool {
	return cs.compound == nil && cs.seed == nil
}

//Turns the coin sleeve into a GOB
func (cs *Sleeve) GobEncode() ([]byte, error) {
	var output []byte

	if cs.seed == nil {
		output = append(output, NilBaseFrame[:]...)
	} else {
		output = append(output, cs.seed[:]...)
	}

	if cs.compound == nil {
		output = append(output, NilBaseFrame[:]...)
	} else {
		output = append(output, cs.compound[:]...)
	}

	valuelist := make([]byte, 8)
	binary.BigEndian.PutUint64(valuelist, cs.value)

	output = append(output, valuelist...)

	return output, nil
}

//Turns a gob into a coin sleeve
func (cs *Sleeve) GobDecode(input []byte) error {

	if uint64(len(input)) != (GobLen) {
		return ErrIncorrectLen
	}

	var seedArr [BaseFrameLen]byte

	copy(seedArr[:], input[GobSeedStart:GobSeedEnd])

	seed, err := DeserializeSeed(seedArr)

	if err != nil {
		cs.seed = nil
	} else {
		cs.seed = &seed
	}

	var compoundArr [BaseFrameLen]byte

	copy(compoundArr[:], input[GobCompoundStart:GobCompoundEnd])

	compound, err := DeserializeCompound(compoundArr)

	if err != nil {
		cs.compound = nil
	} else {
		cs.compound = &compound
	}

	cs.value = binary.BigEndian.Uint64(input[GobValueStart:GobValueEnd])

	return nil
}
