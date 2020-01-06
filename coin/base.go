////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package coin contains the coin and compound data structures,
// and supporting functionality including minting for tests.
package coin

import (
	"encoding/gob"
	"errors"
)

// Header Definitions
const HeaderLen = uint64(1)
const HeaderLoc = uint64(0)
const HeaderEnd = HeaderLoc + HeaderLen

// Hash Definitions for Compound
const HashLenBits = uint64(256)
const HashLen = HashLenBits / 8
const HashStart = HeaderEnd
const HashEnd = HashStart + HashLen

// RNG component Definitions for Seed
const SeedRNGLenBits = uint64(128)
const SeedRNGLen = SeedRNGLenBits / 8
const SeedRNGStart = HeaderEnd
const SeedRNGEnd = SeedRNGStart + SeedRNGLen

// Calculates the number of coins in a compound based upon external data
const DenominationRegStart = HashEnd
const DenominationRegEnd = DenominationRegStart + DenominationRegisterLen

// Base Frame
const BaseFrameLen = HeaderLen + HashLen + DenominationRegisterLen

// Coin Definitions
const CoinHashStart = uint64(0)
const CoinHashEnd = CoinHashStart + HashLen
const CoinDenominationLoc = CoinHashEnd
const CoinDenominationlen = uint64(1)
const CoinLen = HashLen + CoinDenominationlen

// Type for invalid frames
const NilType byte = 0xff

// Storage of an invalid frame for comparison
var NilBaseFrame [BaseFrameLen]byte

// Returnable errors
var ErrInvalidType = errors.New("incorrect type passed for coin serialization")

// init registers the gob
func init() {
	gob.Register(Sleeve{})
	gob.Register([]Sleeve{})

	NilBaseFrame[HeaderLoc] = NilType
}

// IsSeed checks if an array is a seed
func IsSeed(s []byte) bool {
	return s[HeaderLoc] == SeedType
}

// IsCompound checks if an array is a compound
func IsCompound(c []byte) bool {
	return c[HeaderLoc] == CompoundType
}
