package coin

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

//Test that DeserializeCompound only returns a seed when a valid header is passed
func TestDeserializeCompound_Header(t *testing.T) {
	var protoCompound [BaseFrameLen]byte

	for i := 0; i < math.MaxUint8; i++ {
		protoCompound[HeaderLoc] = byte(i)

		_, err := DeserializeCompound(protoCompound)

		if (err == nil) != (byte(i) == CompoundType) {
			t.Errorf("protoCompound: Incorrect response to header %x", i)
		}

	}
}

//Test that DeserializeCompound's output is an exact copy of its input
func TestDeserializeCompound_Output(t *testing.T) {
	var protoCompound [BaseFrameLen]byte

	protoCompound[HeaderLoc] = CompoundType

	seed, err := DeserializeCompound(protoCompound)

	if err != nil {
		t.Errorf("DeserializeSeed: returned error on seed creation: %s", err.Error())
	}

	if !reflect.DeepEqual([BaseFrameLen]byte(seed), protoCompound) {
		t.Errorf("DeserializeSeed: Output not the same as input; Output: %x, Input: %x", seed, protoCompound)
	}
}

// Smoke Test of Compound.Value, it calls the underlying value function which is fully tested
func TestCompound_Value(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Compound.Value: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		value := compound.Value()

		if value != expectedValue {
			t.Errorf("Compound: Value of multiple coins returned does not match expected"+
				"Expected: %v, Received: %v", expectedValue, value)
		}
	}
}

//Test of Compound.Copy showing correctness
func TestCompound_Copy(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Seed.Copy: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		compoundCopy := compound.Copy()

		if !reflect.DeepEqual(compound, compoundCopy) {
			t.Errorf("compound.Copy: copied compound does not match origonal"+
				"Expected: %v, Received: %v", compound, compoundCopy)
		}

		compound[0] = compound[0] + 10

		if reflect.DeepEqual(seed, compoundCopy) {
			t.Errorf("Compound.Copy: copy is linked to origonal")
		}
	}
}

// Shows that verify only returns true when the seed and compound match
func TestCompound_Verify(t *testing.T) {
	numInTest := 20

	src := rand.NewSource(42)
	rng := rand.New(src)

	seedLst := make([]Seed, numInTest)
	compoundLst := make([]Compound, numInTest)

	var err error

	for i := 0; i < numInTest; i++ {
		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seedLst[i], err = NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Compound.Verify: returned error on seed creation: %s", err.Error())
		}

		compoundLst[i] = seedLst[i].ComputeCompound()
	}

	for i := 0; i < numInTest; i++ {
		for j := 0; j < numInTest; j++ {

			if (i == j) != compoundLst[j].Verify(seedLst[i]) {
				t.Errorf("Compound.Verify: Seed/Compound pair %v and %v responded incorrectly", i, j)
			}
		}
	}
}

//Shows that coins that come out have the correct denominations
func TestCompound_ComputeCoins_Denominations(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Compound.Value: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		coinLst := compound.ComputeCoins()

		dr, _ := DeserializeDenominationRegistry(compound[DenominationRegStart:DenominationRegEnd])

		coins := dr.List()

		for indx, coin := range coinLst {
			if coin.GetDenomination() != coins[indx] {
				t.Errorf("Compound.ComputeCoins: coin denomination did not match: Expected: %v, Received: %v",
					coin.GetDenomination(), coins[indx])
			}
		}
	}
}

//Shows that coins differ with different inputs
func TestCompound_ComputeCoins_Randomness(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	var coinSuperList [][]Coin

	for i := 0; i < 20; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Compound.Value: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		coinLst := compound.ComputeCoins()

		dr, _ := DeserializeDenominationRegistry(compound[DenominationRegStart:DenominationRegEnd])

		coins := dr.List()

		coinSuperList = append(coinSuperList, coinLst)

		for indx, coin := range coinLst {
			if coin.GetDenomination() != coins[indx] {
				t.Errorf("Compound.ComputeCoins: coin denomination did not match: Expected: %v, Received: %v",
					coin.GetDenomination(), coins[indx])
			}
		}
	}

	for i := 0; i < 20; i++ {
		for j := 0; j < 20; j++ {
			if i != j {
				for k := 0; k < len(coinSuperList[i]); k++ {
					for l := 0; l < len(coinSuperList[j]); l++ {
						if reflect.DeepEqual(coinSuperList[i][k], coinSuperList[j][l]) {
							t.Errorf("Compound.ComputeCoins: Two Coins matched, which should be impossible")
						}
					}
				}
			}
		}
	}
}
