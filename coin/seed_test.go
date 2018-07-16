package coin

import (
	//"math"
	"math"
	"math/rand"
	"reflect"
	"testing"
)

// Tests that seeds have the correct header type
func TestNewSeed_Header(t *testing.T) {
	seed, err := NewSeed(1)

	if err != nil {
		t.Errorf("NewSeed: returned error on seed creation: %s", err.Error())
	}

	if seed[HeaderLoc] != SeedType {
		t.Errorf("NewSeed: returned seed witht the wrong type header: %x", seed[HeaderLoc])
	}
}

// Tests what happens when the value passed is too low or high
//Tests MinMax values for DenominationRegisters
func TestNewSeed_MinMax(t *testing.T) {
	_, err := NewSeed(0)

	if err == nil {
		t.Errorf("NewSeed: passed an " +
			"invalud value of 0 but no error returned")
	}

	_, err = NewSeed(1 << NumDenominations)

	if err == nil {
		t.Errorf("NewSeed: passed an " +
			"invalud value of 2^16 but no error returned")
	}
}

//Randomness testing of NewSeed
func TestNewSeed_RNG(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	value := rng.Uint64() % MaxValueDenominationRegister

	seed1, err := NewSeed(value)

	if err != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	seed2, err2 := NewSeed(value)

	if err2 != nil {
		t.Errorf("NewSeed: Returned error with properly formatted "+
			"NewSeed(): %s", err.Error())
	}

	if reflect.DeepEqual(seed1, seed2) {
		t.Errorf("NewSeed: Two identical seeds where generated")
	}
}

//Tests random happy path input values for Seed
func TestNewSeed_RandomValues(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		expectedValue := rng.Uint64() % MaxValueDenominationRegister
		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("NewSeed: error returned with valid"+
				"consruction: %s", err.Error())
		}

		deconstructed := uint64(seed[DenominationRegStart]) |
			(uint64(seed[DenominationRegStart+1]) << 8) |
			(uint64(seed[DenominationRegStart+2]) << 16)

		if deconstructed != expectedValue {
			t.Errorf("NewSeed: Incorrect return, "+
				"Expected: %v Recieved: %v", expectedValue, deconstructed)
		}
	}
}

//Test that DeserializeSeed only returns a seed when a valid header is passed
func TestSerializeSeed_Header(t *testing.T) {
	var protoseed Seed

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

// Tests that hashToCompound output is the correct length
func TestSeed_hashToCompound_outputLength(t *testing.T) {
	var seed Seed

	hash := seed.hashToCompound()

	if uint64(len(hash)) != HashLen {
		t.Errorf("HashToCompound: lenght out output is incorrect: expected: %v, recieved: %v",
			HashLen, len(hash))
	}

}

// Smoke Test of Seed.Value, it calls the underlying value function which is fully tested
func TestSeed_Value(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Seed.Value: returned error on seed creation: %s", err.Error())
		}

		value := seed.Value()

		if value != expectedValue {
			t.Errorf("Seed.Value: Value of multiple coins returned does not match expected"+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

//Test of Seed.Copy showing correctness
func TestSeed_Copy(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Seed.Copy: returned error on seed creation: %s", err.Error())
		}

		seedCopy := seed.Copy()

		if !reflect.DeepEqual(seed, seedCopy) {
			t.Errorf("Seed.Copy: copied seed does not match origonal"+
				"Expected: %v, Received: %v", seed, seedCopy)
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
	seed, err := NewSeed(1)

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

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Seed.ComputeCompound: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		if !reflect.DeepEqual(compound[DenominationRegStart:DenominationRegEnd], seed[DenominationRegStart:DenominationRegEnd]) {
			t.Errorf("Seed.ComputeCompound: Denominations not copied correctly; Expected: %x, Received: %x",
				seed[DenominationRegStart:DenominationRegEnd], compound[DenominationRegStart:DenominationRegEnd])
		}

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
