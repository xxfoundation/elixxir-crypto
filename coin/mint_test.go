////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"testing"
)

// Proves that Mint() returns the requested value in one coin
func TestMint_OneCoin(t *testing.T) {
	totalValue := int64(108926)
	coins := mint(totalValue, 6908132, 1)
	if len(coins) != 1 {
		t.Errorf("Expected to get one coin")
	}
	if coins[0].Value() != uint64(totalValue) {
		t.Errorf("Didn't get correct total value for the minted coins. "+
			"Got %v, expected %v", coins[0].Value(), totalValue)
	}
}

// Proves that Mint() returns only valid coins when we want many coins
func TestMint_CentsOnly(t *testing.T) {
	totalValue := int64(100)
	coins := mint(totalValue, 6908132, totalValue)
	if int64(len(coins)) != totalValue {
		t.Errorf("Expected to get %v coins, got %v coins instead",
			totalValue, len(coins))
	}
	for i := range coins {
		if coins[i].Value() != 1 {
			t.Errorf("Expected coin at index %v to have value 1, "+
				"but it had value %v", i, coins[i].Value())
		}
	}
}

// This is an example of typical usage of Mint().
func TestMint_Between(t *testing.T) {
	totalValue := int64(2066958)
	totalCoins := int64(10)
	coins := mint(totalValue, 25993819, totalCoins)
	if int64(len(coins)) != totalCoins {
		t.Errorf("Expected to get %v coins, got %v coins instead",
			totalCoins, len(coins))
	}
	actualValue := uint64(0)
	for i := range coins {
		t.Logf("Coin %v value: %v", i, coins[i].Value())
		actualValue += coins[i].Value()
	}
	if actualValue != uint64(totalValue) {
		t.Errorf("Actual value didn't match expected value. Got: %v, "+
			"expected %v", actualValue, totalValue)
	}
}

// Mint() can panic when you ask for more coins than it can populate with the
// requested value. This shouldn't occur in normal usage.
func TestMint_Panic(t *testing.T) {
	defer Catch("Mint", t)
	mint(1, 1, 15209889243)
}

// Stolen shamelessly from GenerateSharedKey() test functions
func Catch(fn string, t *testing.T) {
	if r := recover(); r != nil {
		println("Good news! Panic was caught!", fn, " Had to trigger recover in", r)
	} else {
		t.Errorf("No panic was caught and it was expected to!")
	}
}

// Proves that for a certain set of users,
// the value is all within some acceptable range
func TestMintArbitrarily(t *testing.T) {
	for user := 1; user < 100; user++ {
		userId := make([]byte, 32)
		userId[len(userId)-1] = byte(user)
		compoundCoins := MintArbitrarily(userId)
		totalValue := uint64(0)
		for i := range compoundCoins {
			totalValue += compoundCoins[i].value
		}
		if totalValue == 0 || totalValue > MaxValueDenominationRegister {
			t.Errorf("Total value %v was out of expected range", totalValue)
		}
		if len(compoundCoins) != 10 {
			t.Error("Expected exactly ten compound coins for this user")
		}
	}
}
