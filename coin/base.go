package coin

/*
import (
	"errors"
	"gitlab.com/privategrity/crypto/format"
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
const NumCompoundsPerPayload = uint64(5)
const MaxCoinsPerCompound = ((format.DATA_LEN / NumCompoundsPerPayload) - HashLen)
const DenominationsStart = HashEnd
const DenominationsLen = MaxCoinsPerCompound
const DenominationsEnd = DenominationsStart + DenominationsLen

//Base Frame
const BaseFrameLen = HeaderLen + HashLen + DenominationsLen

// Defines the size of a coin
const CoinLen = HashLen + 1
const CoinDenominationLoc = CoinLen - 1
const CoinDenominationMask = 0x0F

// Returnable errors
var ErrZeroCoins = errors.New("no denominations passed")
var ErrExcessiveCoins = errors.New("too many denominations passed")
var ErrInvalidType = errors.New("incorrect type passed for serialization")

// Internal function used by both seed and compound to return all Coins
func getCoins(pi [BaseFrameLen]byte) []Denomination {
	var denom []Denomination
	for i := DenominationsStart; i < DenominationsEnd; i++ {
		denom1 := Denomination(pi[i] & 0x0f)

		if denom1 >= 7 {
			break
		}

		denom = append(denom, denom1)

		denom2 := Denomination((pi[i] >> 4) & 0x0f)
		if denom2 >= 9 {
			break
		}

		denom = append(denom, denom2)
	}

	return denom
}

// Internal function used by both seed and compound to return the number of
// Coins
func getNumCoins(pi [BaseFrameLen]byte) uint64 {
	numDenom := uint64(0)
	for i := DenominationsStart; i < DenominationsEnd; i++ {
		denom1 := Denomination(pi[i] & 0x0f)

		if denom1 >= 4 {
			break
		}

		numDenom++

		denom2 := Denomination((pi[i] >> 4) & 0x0f)

		if denom2 >= 4 {
			break
		}

		numDenom++
	}
	return numDenom
}

// Internal function used by both seed and compound to return the sum of
// the value of all coins represented
func value(pi [BaseFrameLen]byte) uint64 {
	v := uint32(0)
	for _, dnm := range getCoins(pi) {
		v += dnm.Value()
	}

	return v
}

// Verifies that denominations in a seed or compound are all valid
func checkDenominationList(denominations []Denomination) error {
	// Check that denominations were passed
	if len(denominations) == 0 {
		return ErrZeroCoins
	}

	// Make sure that the number of subcoins does not exceed the maximum
	if uint64(len(denominations)) > MaxCoinsPerCompound {
		return ErrExcessiveCoins
	}

	// Check the denominations are valid
	for _, denom := range denominations {
		if denom >= 4 {
			return ErrInvalidDenomination
		}
	}

	return nil
}
*/
