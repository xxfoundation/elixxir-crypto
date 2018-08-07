package coin

import (
	"math/rand"
)

// REAL, PALPABLE DANGER INSIDE
// This file contains functionality for creating the actual tokens.
// It's not meant for issuing coins in production, and you should never call
// this, except for testing and demo purposes. STAY AWAY unless you're here to
// delete this before a public release.

// This function creates a predictable set of coins for a particular PRNG seed.
// The payments demo uses this to create coins for the users to move around.
// If more than one coin is allowed, the function will return coins with different values.
// The payment bot and clients will call this function with the same
// predetermined seed. The seeds for all the coins that get created will
// therefore be public, but we won't mint and use other users' coins in the demo
// as a matter of courtesy.

// If you pass this function a total value that's less than the number of coins
// allowed to hold that value, it will panic.
func Mint(totalValue int64, seed int64, numCoins int64) []Sleeve {
	if totalValue < numCoins {
		panic("You're asking me to make fractional coins, which I cannot do!")
	}
	r := rand.New(rand.NewSource(seed))
	result := make([]Sleeve, 0, numCoins)
	for numCoins > 0 {
		// Generate seed for this new coin
		coinSeed := Seed{}
		r.Read(coinSeed[:])
		// Overwrite seed header
		coinSeed[0] = SeedType
		// Overwrite value
		value := getNextValue(r, totalValue, numCoins)
		numCoins--
		totalValue -= int64(value)
		NewDenominationRegistry(coinSeed[uint64(len(
			coinSeed)) - DenominationRegisterLen:], value)
		coinCompound := coinSeed.ComputeCompound()
		result = append(result, ConstructSleeve(&coinSeed, &coinCompound))
	}
	return result
}

func getNextValue(r *rand.Rand, totalValue int64, remainingCoins int64) uint64 {
	// Never return too much value for the other coins to have no value
	nextValue := uint64(r.Int63n(totalValue-(remainingCoins-1)) + 1)
	if remainingCoins == 1 {
		nextValue = uint64(totalValue)
	}
	if nextValue > MaxValueDenominationRegister {
		nextValue = MaxValueDenominationRegister
	}

	return nextValue
}
