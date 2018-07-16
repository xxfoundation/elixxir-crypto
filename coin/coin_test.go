package coin

import (
	"math"
	"testing"
)

// Exhaustively Tests GetPrefix
func TestCoin_GetPrefix(t *testing.T) {

	var coin Coin

	for i := byte(0); i < byte(math.MaxUint8); i++ {
		coin[CoinPrefixLoc] = i

		if coin.GetPrefix() != i {
			t.Errorf("Coin.GetPrefix: Returned the incorrect prefix"+
				" Expected %v, Received: %v", i, coin.GetPrefix())
		}
	}
}

// Exhaustively Tests GetDenomination
func TestCoin_GetDenomination(t *testing.T) {

	var coin Coin

	for i := byte(0); i < byte(NumDenominations); i++ {
		coin[CoinDenominationLoc] = i

		if coin.GetDenomination() != Denomination(i&DenominationMask) {
			t.Errorf("Coin.GetDenomination: Returned the incorrect denomination"+
				" Expected %v, Received: %v", i&DenominationMask, coin.GetDenomination())
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
