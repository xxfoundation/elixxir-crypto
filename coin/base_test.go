package coin

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

//Test the internal GetCoins function when a full set of coins are present
func TestGetCoins_Full(t *testing.T) {
	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, Denomination(i%uint64(NilDenomination)))
	}

	for i := uint64(0); i < (DenominationsLen); i++ {
		tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
	}

	newCoins := getCoins(tstArr)

	if len(coins) != len(newCoins) {
		t.Errorf("getCoins: Number of Coins returned does"+
			" not equal number passed: Passed: %v, Returned: %v", len(coins),
			len(newCoins))
	}

	if !reflect.DeepEqual(coins, newCoins) {
		t.Errorf("getCoins: Coins returned not equal to"+
			" those passed: Passed: %v, Received: %v", coins, newCoins)
	}
}

//Test the internal GetCoins function when a partial set of coins are present
func TestGetCoins_Partial(t *testing.T) {
	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	coins[0] = 3

	for i := uint64(0); i < (DenominationsLen); i++ {
		tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
	}

	newCoins := getCoins(tstArr)

	if len(newCoins) != 1 {
		t.Errorf("getCoins: Number of Coins returned does"+
			" not equal number passed: Passed: 1, Returned: %v", len(newCoins))
	}

	if newCoins[0] != coins[0] {
		t.Errorf("getCoins: Coins returned not equal to" +
			" those passed")
	}
}

//Test the internal getNumCoins function when a full set of coins are present
func TestGetNumCoins_Full(t *testing.T) {
	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, Denomination(i%uint64(NilDenomination)))
	}

	for i := uint64(0); i < (DenominationsLen); i++ {
		tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
	}

	newCoins := getNumCoins(tstArr)

	if uint64(len(coins)) != newCoins {
		t.Errorf("getNumCoins: Number of Coins returned does"+
			" not equal number passed: Passed: %v, Returned: %v", len(coins),
			newCoins)
	}
}

//Test the internal getNumCoins function when a partial set of coins are present
func TestGetNumCoins_Partial(t *testing.T) {
	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	coins[0] = 3

	for i := uint64(0); i < (DenominationsLen); i++ {
		tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
	}

	newCoins := getCoins(tstArr)

	if len(newCoins) != 1 {
		t.Errorf("getNumCoins: Number of Coins returned does"+
			" not equal number passed: Passed: %v, Returned: %v", len(coins),
			len(newCoins))
	}
}

//Tests the internal value function with only a single coin
func TestValue_Single(t *testing.T) {

	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
		coins = append(coins, NilDenomination)
	}

	for i := Denomination(0); i < NumDenominations; i++ {
		coins[0] = i

		for i := uint64(0); i < DenominationsLen; i++ {
			tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
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

	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		coins = []Denomination{}
		for i := uint64(0); i < (MaxCoinsPerCompound); i++ {
			coins = append(coins, NilDenomination)
		}

		numCoins := rng.Uint64() % MaxCoinsPerCompound

		expectedValue := uint64(0)

		for i := uint64(0); i < numCoins; i++ {
			coin := Denomination(rng.Uint64() % uint64(NilDenomination))
			coins[i] = coin

			expectedValue += coin.Value()
		}

		for i := uint64(0); i < (DenominationsLen); i++ {
			tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
		}

		value := value(tstArr)

		if value != expectedValue {
			t.Errorf("value: Value of multiple coins returned does not match expected"+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

//Tests the internal value function with max number of coins
func TestValue_MaxCoins(t *testing.T) {

	var tstArr [BaseFrameLen]byte
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		coins = []Denomination{}

		expectedValue := uint64(0)

		for i := uint64(0); i < MaxCoinsPerCompound; i++ {
			coin := Denomination(rng.Uint64() % uint64(NumDenominations))
			coins = append(coins, coin)

			expectedValue += coin.Value()
		}

		for i := uint64(0); i < (DenominationsLen); i++ {
			tstArr[DenominationsStart+i] = byte(coins[2*i] | coins[2*i+1]<<4)
		}

		value := value(tstArr)

		if value != expectedValue {
			t.Errorf("value: Value of max coins returned does not match expected"+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

// Tests that checkDenominationList returns an error when passed an empty denomination list
func TestCheckDenominationList_Empty(t *testing.T) {
	err := checkDenominationList([]Denomination{})
	if err != ErrZeroCoins {
		if err == nil {
			t.Errorf("checkDenominationList: Returned no error when passed empty list")
		} else {
			t.Errorf("checkDenominationList: Returned incorrect error when passed "+
				"empty list: %s", err.Error())
		}
	}
}

// Tests that checkDenominationList returns an error when passed too many denominations
func TestCheckDenominationListFirst_TooMany(t *testing.T) {

	dlst := make([]Denomination, MaxCoinsPerCompound+1)

	err := checkDenominationList(dlst)
	if err != ErrExcessiveCoins {
		if err == nil {
			t.Errorf("checkDenominationList: Returned no error when passed excessive coins")
		} else {
			t.Errorf("checkDenominationList: Returned incorrect error when passed "+
				"excessive coins: %s", err.Error())
		}
	}
}

// Tests that checkDenominationList returns an error on invalid coins an no errors on valid coins exhaustively
func TestCheckDenominationListFirst_ValidExhaustive(t *testing.T) {

	for i := Denomination(0); i < Denomination(255); i++ {
		err := checkDenominationList([]Denomination{i})

		if i < NumDenominations {
			if err != nil {
				t.Errorf("checkDenominationList: Returned error on valid coin %x: %s", i, err.Error())
			}
		} else {
			if err != ErrInvalidDenomination {
				if err == nil {
					t.Errorf("checkDenominationList: Returned no error when passed invalid coin %x", i)
				} else {
					t.Errorf("checkDenominationList: Returned incorrect error when passed invalid coin %x: %s",
						i, err.Error())
				}
			}
		}
	}

}

//Tests that IsSeed returns false on all headers except for seed
func TestIsSeed_False(t *testing.T) {
	var tst [BaseFrameLen]byte
	for i := byte(0); i < byte(math.MaxUint8); i++ {
		if i != SeedType {
			tst[HeaderLoc] = i
			if IsSeed(tst) {
				t.Errorf("IsSeed: Returned true for input %x which is not a seed",
					i)
			}
		}
	}
}

//Tests that IsSeed returns true for a seed header
func TestIsSeed_True(t *testing.T) {
	var tst [BaseFrameLen]byte
	tst[HeaderLoc] = SeedType
	if !IsSeed(tst) {
		t.Errorf("IsSeed: Returned false for unput %x which is a seed",
			SeedType)
	}
}

//Tests that IsCompound returns false on all headers except for seed
func TestIsCompound_False(t *testing.T) {
	var tst [BaseFrameLen]byte
	for i := byte(0); i < byte(math.MaxUint8); i++ {
		if i != CompoundType {
			tst[HeaderLoc] = i
			if IsCompound(tst) {
				t.Errorf("IsCompound: Returned true for input %x which is not a compound",
					i)
			}
		}
	}
}

//Tests that IsSeed returns true for a seed header
func TestIsCompound_True(t *testing.T) {
	var tst [BaseFrameLen]byte
	tst[HeaderLoc] = CompoundType
	if !IsCompound(tst) {
		t.Errorf("IsCompound: Returned false for unput %x which is a compound",
			CompoundType)
	}
}
