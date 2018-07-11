package coin

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

// Tests that seeds have the correct header type
func TestNewSeed_Header(t *testing.T) {
	seed, err := NewSeed([]Denomination{1})

	if err != nil {
		t.Errorf("NewSeed: returned error on seed creation: %s", err.Error())
	}

	if seed[HeaderLoc] != SeedType {
		t.Errorf("NewSeed: returned seed witht the wrong type header: %x", seed[HeaderLoc])
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
				" Expected: %v, Received: %v", denom[i], newDenom[i])
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
				" return with the expected length: Expected %v, Received: %v",
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

//Test that DeserializeSeed only returns a seed when a valid header is passed
func TestSerializeSeed_Header(t *testing.T) {
	var protoseed [BaseFrameLen]byte

	for i := 0; i < math.MaxUint8; i++ {
		protoseed[HeaderLoc] = byte(i)

		_, err := DeserializeSeed(protoseed)

		if (err == nil) != (byte(i) == SeedType) {
			t.Errorf("DeserializeSeed: Incorrect response to header %x", i)
		}

	}
}

//Test that DeserializeSeed's output is an exact copy of its input
func TestSerializeSeed_Output(t *testing.T) {
	var protoseed [BaseFrameLen]byte

	protoseed[HeaderLoc] = SeedType

	seed, err := DeserializeSeed(protoseed)

	if err != nil {
		t.Errorf("DeserializeSeed: returned error on seed creation: %s", err.Error())
	}

	if !reflect.DeepEqual([BaseFrameLen]byte(seed), protoseed) {
		t.Errorf("DeserializeSeed: Output not the same as input; Output: %x, Input: %x", seed, protoseed)
	}
}

// Tests that hashToCompound only hashes the correct bits
func TestSeed_hashToCompound(t *testing.T) {
	var base Seed

	baseHash := base.hashToCompound()

	for i := uint64(0); i < BaseFrameLen; i++ {
		base[i] = 255

		newHash := base.hashToCompound()

		if i >= SeedRNGStart && i < SeedRNGEnd {
			if reflect.DeepEqual(baseHash, newHash) {
				t.Errorf("HashToCompound: edit of byte %v should have changed the hash but did not", i)
			}
		} else {
			if !reflect.DeepEqual(baseHash, newHash) {
				t.Errorf("HashToCompound: edit of byte %v should not changed the hash but did", i)
			}
		}

		base[i] = 0
	}

}

// Smoke Test of Seed.GetCoins, it calls the underlying value function which is fully tested
func TestSeed_GetCoins(t *testing.T) {
	var coins []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		coins = append(coins, Denomination(i)%NumDenominations)

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Seed.GetCoins: returned error on seed creation: %s", err.Error())
		}

		newCoins := seed.GetCoins()

		if !reflect.DeepEqual(coins, newCoins) {
			t.Errorf("Seed.GetCoins: Coins returned do"+
				" not match those passed: Passed: %v, Returned: %v", coins,
				newCoins)
		}

	}
}

// Smoke Test of Seed.GetNumCoins, it calls the underlying value function which is fully tested
func TestSeed_GetNumCoins(t *testing.T) {
	var coins []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		coins = append(coins, Denomination(i)%NumDenominations)

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Seed.GetCoins: returned error on seed creation: %s", err.Error())
		}

		numCoins := seed.GetNumCoins()

		if numCoins != uint64(len(coins)) {
			t.Errorf("Seed.GetNumCoins: Incorrect number of coins"+
				" returned: Passed: %v, Returned: %v", len(coins),
				numCoins)
		}

	}
}

// Smoke Test of Seed.Value, it calls the underlying value function which is fully tested
func TestSeed_Value(t *testing.T) {
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		coins = []Denomination{}

		numCoins := (rng.Uint64() % (MaxCoinsPerCompound - 1)) + 1

		expectedValue := uint64(0)

		for i := uint64(0); i < numCoins; i++ {
			coin := Denomination(rng.Uint64() % uint64(NumDenominations))
			coins = append(coins, coin)

			expectedValue += coin.Value()
		}

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Seed.Value: returned error on seed creation: %s", err.Error())
		}

		value := seed.Value()

		if value != expectedValue {
			t.Errorf("value: Value of multiple coins returned does not match expected"+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

// Tests that Seed.GetPrefix returns the correct bytes
func TestSeed_GetPrefix(t *testing.T) {
	var seed Seed

	for i := byte(0); i < byte(BaseFrameLen); i++ {
		seed[i] = i
	}

	expectedPrefix := seed[SeedPrefixStart:SeedPrefixEnd]

	receivedPrefix := seed.GetPrefix()

	if !reflect.DeepEqual(expectedPrefix, receivedPrefix) {
		t.Errorf("Seed.GetPrefix: Returned prefix not equal to expected"+
			"Expected: %v, Received: %v", expectedPrefix, receivedPrefix)
	}

}

// Tests that the header in compound is correct
func TestSeed_ComputeCompound_Header(t *testing.T) {
	seed, err := NewSeed([]Denomination{1})

	if err != nil {
		t.Errorf("Seed.ComputeCompound: returned error on seed creation: %s", err.Error())
	}

	compound := seed.ComputeCompound()

	if compound[HeaderLoc] != CompoundType {
		t.Errorf("Seed.ComputeCompound: Compound created with incorrect type: %x", compound[HeaderLoc])
	}
}

//Shows that the denominations are copied from the seed to the compound properly
func TestSeed_ComputeCompound_Denominations(t *testing.T) {
	seed, err := NewSeed([]Denomination{1})

	if err != nil {
		t.Errorf("Seed.ComputeCompound: returned error on seed creation: %s", err.Error())
	}

	compound := seed.ComputeCompound()

	if !reflect.DeepEqual(compound[DenominationsStart:DenominationsEnd], seed[DenominationsStart:DenominationsEnd]) {
		t.Errorf("Seed.ComputeCompound: Denominations not copied correctly; Expected: %x, Received: %x", seed[DenominationsStart:DenominationsEnd], compound[DenominationsStart:DenominationsEnd])
	}

}

//Shows that the hash in the compound is sourced only from the rng section of the coin
func TestSeed_ComputeCompound_HashSource(t *testing.T) {
	var base Seed

	baseCompound := base.ComputeCompound()

	for i := uint64(0); i < BaseFrameLen; i++ {
		base[i] = 255

		compound := base.ComputeCompound()

		if i >= SeedRNGStart && i < SeedRNGEnd {
			if reflect.DeepEqual(baseCompound[HashStart:HashEnd], compound[HashStart:HashEnd]) {
				t.Errorf("Seed.ComputeCompound: edit of byte %v should have changed the hash but did not", i)
			}
		} else {
			if !reflect.DeepEqual(baseCompound[HashStart:HashEnd], compound[HashStart:HashEnd]) {
				t.Errorf("Seed.ComputeCompound: edit of byte %v should not have changed the hash but did", i)
			}
		}

		base[i] = 0
	}

}
