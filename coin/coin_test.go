////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"testing"
)

// Exhaustively Tests GetDenomination
func TestCoin_GetDenomination(t *testing.T) {

	var coin Coin

	for i := byte(0); i < byte(NumDenominations); i++ {
		coin[CoinDenominationLoc] = i

		if coin.GetDenomination() != Denomination(i) {
			t.Errorf("Coin.GetDenomination: Returned the incorrect denomination"+
				" Expected %v, Received: %v", i, coin.GetDenomination())
		}
	}
}

// Exhaustively Tests Value
func TestCoin_Value(t *testing.T) {

	var coin Coin

	for i := byte(0); i < byte(NumDenominations); i++ {
		coin[CoinDenominationLoc] = i

		expectedValue := uint64(1 << uint64(i))

		if coin.Value() != expectedValue {
			t.Errorf("Coin.GetValue: Returned the incorrect value"+
				" Expected %v, Received: %v", expectedValue, coin.Value())
		}
	}
}
