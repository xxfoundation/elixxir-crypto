////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"encoding/binary"
)

//Gob definitions
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

// NewSleeve builds a new coin inside of a coinsleeve
func NewSleeve(value uint64) (Sleeve, error) {

	seed, err := NewSeed(value)

	if err != nil {
		return Sleeve{}, err
	}

	compound := seed.ComputeCompound()

	return Sleeve{&seed, &compound, value}, nil
}

// ConstructSleeve constructs a Sleeve from a seed pointer and a compound pointer.
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

// IsMine tells the user if they own the coin
func (cs Sleeve) IsMine() bool {
	return cs.seed != nil
}

// Seed returns a pointer to a copy of the seed
// Returns nil if there is no seed
func (cs Sleeve) Seed() *Seed {
	if cs.seed == nil {
		return nil
	}

	seedCopy := cs.seed.Copy()

	return &seedCopy
}

// Compound returns a pointer to a copy of the compound
// Returns nil if there is no compound
func (cs Sleeve) Compound() *Compound {
	if cs.compound == nil {
		return nil
	}
	compoundCopy := cs.compound.Copy()

	return &compoundCopy
}

// Value returns a copy of the value
func (cs Sleeve) Value() uint64 {
	return cs.value
}

// IsNil returns if the sleeve is nil
func (cs Sleeve) IsNil() bool {
	return cs.compound == nil && cs.seed == nil
}

// GobEncode turns the coin sleeve into a GOB
func (cs *Sleeve) GobEncode() ([]byte, error) {
	var output []byte

	//Serialize the seed into bytes
	if cs.seed == nil {
		output = append(output, NilBaseFrame[:]...)
	} else {
		output = append(output, cs.seed[:]...)
	}

	//Serialize the compound into bytes
	if cs.compound == nil {
		output = append(output, NilBaseFrame[:]...)
	} else {
		output = append(output, cs.compound[:]...)
	}

	valueList := make([]byte, 8)
	binary.BigEndian.PutUint64(valueList, cs.value)

	output = append(output, valueList...)

	return output, nil
}

// GobDecode turns a gob into a coin sleeve
func (cs *Sleeve) GobDecode(input []byte) error {
	//If input is not expected length, return error
	if uint64(len(input)) != (GobLen) {
		return ErrIncorrectLen
	}

	//Deserialize the seed from the gob
	var seedArr [BaseFrameLen]byte
	copy(seedArr[:], input[GobSeedStart:GobSeedEnd])
	seed, err := DeserializeSeed(seedArr)

	//Check for errors
	if err != nil {
		cs.seed = nil
	} else {
		cs.seed = &seed
	}

	//Deserialize the compound from the gob
	var compoundArr [BaseFrameLen]byte
	copy(compoundArr[:], input[GobCompoundStart:GobCompoundEnd])
	compound, err := DeserializeCompound(compoundArr)

	//Check for errors
	if err != nil {
		cs.compound = nil
	} else {
		cs.compound = &compound
	}

	//Set the value of the sleeve
	cs.value = binary.BigEndian.Uint64(input[GobValueStart:GobValueEnd])

	return nil
}
