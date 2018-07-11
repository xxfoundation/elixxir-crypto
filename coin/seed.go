package coin

import (
	"crypto/sha256"
	"gitlab.com/privategrity/crypto/cyclic"
)

// A Seed contains the secret proving ownership of a series of coins
type Seed [BaseFrameLen]byte

// Seed Header
const SeedType byte = 0x55

// Creates a new randomized seed defining coins of the passed denominations
func NewSeed(denominations []Denomination) (Seed, error) {

	//Check that the denominations are valid
	if err := checkDenominationList(denominations); err != nil {
		return Seed{}, err
	}

	//Generate the seed
	p, err := cyclic.GenerateRandomBytes(int(SeedRNGLen))
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

	//Append Nil Denominations to the Denomination List
	for i := uint64(len(denominations)); i < MaxCoinsPerCompound; i++ {
		denominations = append(denominations, NilDenomination)
	}

	//Append the denominations to the coin
	for i := uint64(0); i < DenominationsLen; i++ {
		// Packs two 4 bit denominations into 1 byte
		seed[DenominationsStart+i] = byte(denominations[2*i+1]<<4 | denominations[2*i])
	}

	//Compute the Compound hash
	compoundHash := seed.hashToCompound()

	//Append the compound prefix to the seed
	for i := uint64(0); i < SeedPrefixLen; i++ {
		seed[SeedPrefixStart+i] = compoundHash[i]
	}

	return seed, nil
}

// Produces a seed serialized from an array.  Does not verify the prefix.
func SerializeSeed(protoSeed [BaseFrameLen]byte) (Seed, error) {
	//Check that the header is correct
	if protoSeed[HeaderLoc] != SeedType {
		return Seed{}, ErrInvalidType
	}

	//Check that the denomination list is valid
	if err := checkDenominationList(getCoins(protoSeed)); err != nil {
		return Seed{}, err
	}

	return Seed(protoSeed), nil
}

// Hashes the rng of the seed to generate the hash for a compound
func (seed Seed) hashToCompound() []byte {
	h := sha256.New()

	h.Write(seed[SeedRNGStart:SeedRNGEnd])

	hashed := h.Sum(nil)

	return hashed
}

// Returns a list of the denominations of all coins defined in the seed
func (seed Seed) GetCoins() []Denomination {
	return getCoins(seed)
}

// Returns the Number of coins defined by a seed
func (seed Seed) GetNumCoins() uint64 {
	return getNumCoins(seed)
}

// Returns the value of all coins defined by a seed
func (seed Seed) Value() uint64 {
	return value(seed)
}

// Returns the prefix fo the seed
func (seed Seed) GetPrefix() []byte {
	return seed[SeedPrefixStart:SeedPrefixEnd]
}

//Computes and returns a compound for a given seed
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
	for i := DenominationsStart; i < DenominationsEnd; i++ {
		compound[i] = seed[i]
	}

	return compound
}
