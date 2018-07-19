package coin

import (
	"errors"
)

// Header Definitions
const HeaderLen = uint64(1)
const HeaderLoc = uint64(0)
const HeaderEnd = HeaderLoc + HeaderLen

// Hash Definitions for Compound
const HashLenBits = uint64(160)
const HashLen = HashLenBits / 8
const HashStart = HeaderEnd
const HashEnd = HashStart + HashLen

// RNG component Definitions for Seed
const SeedRNGLenBits = uint64(128)
const SeedRNGLen = SeedRNGLenBits / 8
const SeedRNGStart = HeaderEnd
const SeedRNGEnd = SeedRNGStart + SeedRNGLen

// Prefix component Definitions for Seed
const SeedPrefixLen = HashLen - SeedRNGLen
const SeedPrefixStart = SeedRNGEnd
const SeedPrefixEnd = SeedPrefixStart + SeedPrefixLen

// Calculates the number of coins in a compound based upon external data
const DenominationRegStart = HashEnd
const DenominationRegEnd = DenominationRegStart + DenominationRegisterLen

//Base Frame
const BaseFrameLen = HeaderLen + HashLen + DenominationRegisterLen

// Defines coin prefixes
const CoinPrefixLen = uint64(1)
const CoinPrefixLoc = uint64(0)

const CoinHashStart = CoinPrefixLoc
const CoinHashEnd = CoinHashStart + HashLen + 1
const CoinDenominationLoc = CoinHashEnd - 1
const CoinDenominationlen = uint64(1)
const CoinLen = CoinPrefixLen + HashLen + CoinDenominationlen

const PrefixSourceLoc = HashStart

// Returnable errors
var ErrInvalidType = errors.New("incorrect type passed for coin serialization")

// Checks if an array is a seed
func IsSeed(s []byte) bool {
	return s[HeaderLoc] == SeedType
}

// Checks if an array is a compound
func IsCompound(c []byte) bool {
	return c[HeaderLoc] == CompoundType
}
