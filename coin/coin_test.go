package coin

import (
	"testing"
)

// Tests what happens when no denominations are passed
func TestNewSeed_ZeroDenom(t *testing.T) {
	_, err := NewSeed([]Denomination{})

	if err != ErrZeroCoins {
		if err == nil {
			t.Errorf("NewSeed: Coin returned when no denominations " +
				"passed")
		} else {
			t.Errorf("NewCoinPreimage Coin returned with unexpected error "+
				"when no denominations passed: %s", err.Error())
		}

	}
}

// Tests what happens when too many denominations are passed
func TestNewSeed_TooManyDenom(t *testing.T) {
	var denom []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound + 1); i++ {
		denom = append(denom, Denomination(i%uint64(NilDenomination)))
	}

	_, err := NewSeed(denom)

	if err != ErrExcessiveCoins {
		if err == nil {
			t.Errorf("NewSeed: Coin returned when too may denominations" +
				" passed")
		} else {
			t.Errorf("NewSeed: Coin returned with incorreeect error when" +
				" too many denominations passed")
		}

	}
}
