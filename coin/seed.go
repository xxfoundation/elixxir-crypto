////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"crypto/sha256"
	"gitlab.com/elixxir/crypto/csprng"
)

// A Seed contains the secret proving ownership of a series of coins
type Seed [BaseFrameLen]byte

// Seed Header
const SeedType byte = 0x55

// NewSeed creates a new randomized seed defining coins of the passed denominations
func NewSeed(value uint64) (Seed, error) {

	dr, err := NewDenominationRegistry([]byte{0, 0, 0}, value)

	//Check that the denominations are valid
	if err != nil {
		return Seed{}, err
	}

	//Generate the seed
	rng := csprng.SystemRNG{}
	p := make([]byte, SeedRNGLen)
	_, err = rng.Read(p)
	if err != nil {
		return Seed{}, err
	}

	var seed Seed

	//Set the header
	seed[HeaderLoc] = byte(SeedType)

	//Convert the image to an array
	for i, pi := range p {
		seed[SeedRNGStart+uint64(i)] = pi
	}

	//Append the denomination register to the coin
	for i := uint64(0); i < DenominationRegisterLen; i++ {
		seed[DenominationRegStart+i] = dr[i]
	}

	return seed, nil
}

// DeserializeSeed produces a seed deserialized from an array.  Does not verify the prefix.
func DeserializeSeed(protoSeed [BaseFrameLen]byte) (Seed, error) {

	//Check that the header is correct
	if protoSeed[HeaderLoc] != SeedType {
		return Seed{}, ErrInvalidType
	}

	return Seed(protoSeed), nil
}

// hashToCompound hashes the rng of the seed to generate the hash for a compound
func (seed Seed) hashToCompound() []byte {
	h := sha256.New()

	h.Write(seed[SeedRNGStart:SeedRNGEnd])

	hashed := h.Sum(nil)

	return hashed[:HashLen]
}

// Value returns the sum of the value of all coins defined by a seed
func (seed Seed) Value() uint64 {
	dr, _ := DeserializeDenominationRegistry(seed[DenominationRegStart:DenominationRegEnd])
	return dr.Value()
}

// Copy returns a copy of the seed
func (seed Seed) Copy() Seed {
	var cpy Seed
	copy(cpy[:], seed[:])
	return cpy
}

// ComputeCompound computes and returns a compound for a given seed
func (seed Seed) ComputeCompound() Compound {
	//Hash the seed
	seedHash := seed.hashToCompound()

	var compound Compound

	//Set the compoundHeader
	compound[HeaderLoc] = CompoundType

	//Copy the hash to the compound
	for i, sh := range seedHash {
		compound[HashStart+uint64(i)] = sh
	}

	//Copy the denominations over from the coin
	for i := DenominationRegStart; i < DenominationRegEnd; i++ {
		compound[i] = seed[i]
	}

	return compound
}
