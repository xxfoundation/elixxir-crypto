package coin

import (
	"reflect"
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
			t.Errorf("NewSeed: Coin returned with incorreeect error when"+
				" too many denominations passed: %s", err.Error())
		}

	}
}

// Tests that the system rejects coins with invalid denominations
func TestNewSeed_InvalidDenom(t *testing.T) {
	denom := []Denomination{Denominations}

	_, err := NewSeed(denom)

	if err != ErrInvalidDenomination {
		if err == nil {
			t.Errorf("NewSeed: Coin returned a coin when an invalid" +
				" denomination was passed")
		} else {
			t.Errorf("NewSeed: Coin returned with incorreeect error when"+
				" an invalid denomination passed: %s", err.Error())
		}

	}
}

// Tests that the denominations are stored as the correct values in the correct
// locations in the seed
func TestNewSeed_DenominationPlacement(t *testing.T) {
	var denom []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		denom = append(denom, Denomination(i%uint64(NilDenomination)))
	}

	seed, err := NewSeed(denom)

	if err != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		denom1 := Denomination(seed[HashLen+i] & 0x0f)

		if denom1 != denom[2*i] {
			t.Errorf("NewSeed: Placed Denomination does not match:"+
				" Expected: %v, Recieved: %v", denom[2*i], denom1)
		}

		denom2 := Denomination((seed[HashLen+i] >> 4) & 0x0f)

		if denom2 != denom[2*i+1] {
			t.Errorf("NewSeed: Placed Denomination does not match:"+
				" Expected: %v, Recieved: %v", denom[2*i+1], denom2)
		}
	}
}

// Tests that unused denomination slots are filled with null denominations
func TestNewSeed_NilDenominationPlacement(t *testing.T) {
	denom := []Denomination{3}

	seed, err := NewSeed(denom)

	if err != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	var expectedDenoms []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		expectedDenoms = append(expectedDenoms, NilDenomination)
	}

	expectedDenoms[0] = 3

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		denom1 := Denomination(seed[HashLen+i] & 0x0f)

		if denom1 != expectedDenoms[2*i] {
			t.Errorf("NewSeed: Placed Denomination in nil tes does not"+
				" match: Expected: %v, Recieved: %v", denom[2*i], denom1)
		}

		denom2 := Denomination((seed[HashLen+i] >> 4) & 0x0f)

		if denom2 != expectedDenoms[2*i+1] {
			t.Errorf("NewSeed: Placed Denomination in nil test does not"+
				" match: Expected: %v, Recieved: %v", denom[2*i+1], denom2)
		}
	}
}

//Randomness testing of NewSeed
func TestNewSeed(t *testing.T) {
	var denom []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		denom = append(denom, Denomination(i%uint64(NilDenomination)))
	}

	seed1, err := NewSeed(denom)

	if err != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	seed2, err2 := NewSeed(denom)

	if err2 != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	if reflect.DeepEqual(seed1, seed2) {
		t.Errorf("NewSeed: Two identical seeds where generated")
	}

}
