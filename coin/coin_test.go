package coin

import (
	"math/rand"
	"reflect"
	"testing"
)

//Test the internal GetCoins function when a full set of coins are present
func TestGetCoins_Full(t *testing.T) {
	var tstArr [CompoundLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, Denomination(i%uint64(NilDenomination)))
	}

	for i := uint64(0); i < (CompoundLen - HashLen); i++ {
		tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
	}

	newCoins := getCoins(tstArr)

	if len(coins) != len(newCoins) {
		t.Errorf("getCoins: Number of Coins returned does"+
			" not equal nummer passed: Passed: %v, Returned: %v", len(coins),
			len(newCoins))
	}

	if !reflect.DeepEqual(coins, newCoins) {
		t.Errorf("getCoins: Coins returned not equal to"+
			" those passed: Passed: %v, Recieved: %v", coins, newCoins)
	}
}

//Test the internal GetCoins function when a partial set of coins are present
func TestGetCoins_Partial(t *testing.T) {
	var tstArr [CompoundLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	coins[0] = 3

	for i := uint64(0); i < (CompoundLen - HashLen); i++ {
		tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
	}

	newCoins := getCoins(tstArr)

	if len(newCoins) != 1 {
		t.Errorf("getCoins: Number of Coins returned does"+
			" not equal nummer passed: Passed: 1, Returned: %v", len(newCoins))
	}

	if newCoins[0] != coins[0] {
		t.Errorf("getCoins: Coins returned not equal to" +
			" those passed")
	}
}

//Test the internal getNumCoins function when a full set of coins are present
func TestGetNumCoins_Full(t *testing.T) {
	var tstArr [CompoundLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, Denomination(i%uint64(NilDenomination)))
	}

	for i := uint64(0); i < (CompoundLen - HashLen); i++ {
		tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
	}

	newCoins := getNumCoins(tstArr)

	if uint64(len(coins)) != newCoins {
		t.Errorf("getNumCoins: Number of Coins returned does"+
			" not equal nummer passed: Passed: %v, Returned: %v", len(coins),
			newCoins)
	}
}

//Test the internal getNumCoins function when a partial set of coins are present
func TestGetNumCoins_Partial(t *testing.T) {
	var tstArr [CompoundLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	coins[0] = 3

	for i := uint64(0); i < (CompoundLen - HashLen); i++ {
		tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
	}

	newCoins := getCoins(tstArr)

	if len(newCoins) != 1 {
		t.Errorf("getNumCoins: Number of Coins returned does"+
			" not equal nummer passed: Passed: %v, Returned: %v", len(coins),
			len(newCoins))
	}
}

//Tests the internal value function with only a single coin
func TestValue_Single(t *testing.T) {

	var tstArr [CompoundLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	for i := Denomination(0); i < NumDenominations; i++ {
		coins[0] = i

		for i := uint64(0); i < (CompoundLen - HashLen); i++ {
			tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
		}

		v := value(tstArr)

		if v != i.Value() {
			t.Errorf("value: Value of single coin returned does not "+
				"match: Expected: %v, Received: %v", i, v)
		}
	}
}

//Tests the internal value function with multiple coins but not max coins
func TestValue_Partial(t *testing.T) {

	var tstArr [CompoundLen]byte
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
			coins = append(coins, NilDenomination)
		}

		numCoins := rng.Uint64() % MaxCoinsPerCompound

		expectedValue := uint64(0)

		for i := uint64(0); i < numCoins; i++ {
			coin := Denomination(rng.Uint64() % uint64(NumDenominations))
			coins[i] = coin

			expectedValue += coin.Value()
		}

		for i := uint64(0); i < (CompoundLen - HashLen); i++ {
			tstArr[HashLen+i] = byte(coins[2*i]<<4 | coins[2*i+1])
		}

		value := value(tstArr)

		if value != expectedValue {
			t.Errorf("value: Value of multiple coins returned does not "+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

// Tests what happens when no denominations are passed
func TestNewSeed_ZeroDenom(t *testing.T) {
	_, err := NewSeed([]Denomination{})

	if err != ErrZeroCoins {
		if err == nil {
			t.Errorf("NewSeed: Coin returned when no denominations " +
				"passed")
		} else {
			t.Errorf("NewSeed: Coin returned with unexpected error "+
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
	denom := []Denomination{NumDenominations}

	_, err := NewSeed(denom)

	if err != ErrInvalidDenomination {
		if err == nil {
			t.Errorf("NewSeed: Coin returned a coin when an invalid" +
				" denomination was passed")
		} else {
			t.Errorf("NewSeed: Coin returned with incorreect error when"+
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

	newDenom := getCoins(seed)

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {

		if newDenom[i] != denom[i] {
			t.Errorf("NewSeed: Placed Denomination does not match:"+
				" Expected: %v, Recieved: %v", denom[i], newDenom[i])
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

	newDenom := getCoins(seed)

	if len(newDenom) != 1 {
		if err != nil {
			t.Errorf("NewSeed: Partially filled denomination list did not"+
				" return with the expected length: Expected %v, Recieved: %v",
				1, len(newDenom))
		}
	}
}

//Randomness testing of NewSeed
func TestNewSeed_RNG(t *testing.T) {
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
