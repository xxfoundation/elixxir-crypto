package coin

import (
	jww "github.com/spf13/jwalterweatherman"
	"math/rand"
)

// This function creates a deterministic set of coins for a particular PRNG
// seed. The payments demo uses this to create coins for the users to move
// around. If more than one compound coin is allowed, the function will
// probably return compounds with steadily decreasing values. The payment bot
// and clients will call this function with the same predetermined seed to
// populate their wallets with compounds with a realistic distribution of
// denominations. The seeds for all the coins that get created will therefore
// be public, but the CUI and client command line will only mint the coins that
// belong to the user they're running for.

// To remove this once more robust functionality for issuing tokens is in
// place, recursive grep ignoring case for Mint in
// $GOPATH/gitlab.com/privategrity. Doing this should reveal the location of
// all related functionality.

// If you pass this function a total value that's less than the number of coins
// allowed to hold that value, it will panic.
func Mint(totalValue int64, prngSeed int64, numSleeves int64) []Sleeve {
	jww.WARN.Printf("Minting %v compound coins. Don't do this except for demos"+
		" or testing.", numSleeves)
	if totalValue < numSleeves {
		panic("Too many compound coins requested, not enough value for each of them")
	}
	r := rand.New(rand.NewSource(prngSeed))
	result := make([]Sleeve, 0, numSleeves)
	for numSleeves > 0 {
		// Generate seed for this new coin
		seed := Seed{}
		r.Read(seed[:])
		// Overwrite seed header
		seed[0] = SeedType
		// Overwrite value
		value := getNextValue(r, totalValue, numSleeves)
		numSleeves--
		totalValue -= int64(value)
		NewDenominationRegistry(seed[uint64(len(
			seed))-DenominationRegisterLen:], value)
		compound := seed.ComputeCompound()
		result = append(result, ConstructSleeve(&seed, &compound))
	}
	return result
}

func getNextValue(r *rand.Rand, totalValue int64, remainingSleeves int64) uint64 {
	// Never return too much value for the other coins to have no value
	nextValue := uint64(r.Int63n(totalValue-(remainingSleeves-1)) + 1)
	if remainingSleeves == 1 {
		nextValue = uint64(totalValue)
	}
	if nextValue > MaxValueDenominationRegister {
		nextValue = MaxValueDenominationRegister
	}

	return nextValue
}
