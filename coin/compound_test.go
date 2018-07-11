package coin

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

//Test that DeserializeCompound only returns a seed when a valid header is passed
func TestSerializeCompound_Header(t *testing.T) {
	var protoCompound [BaseFrameLen]byte

	for i := 0; i < math.MaxUint8; i++ {
		protoCompound[HeaderLoc] = byte(i)

		_, err := DeserializeCompound(protoCompound)

		if (err == nil) != (byte(i) == CompoundType) {
			t.Errorf("protoCompound: Incorrect responce to headder %x", i)
		}

	}
}

//Test that DeserializeCompound's output is an exact copy of its input
func TestSerializeCompound_Output(t *testing.T) {
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

// Smoke Test of Compound.GetCoins, it calls the underlying value function which is fully tested
func TestCompound_GetCoins(t *testing.T) {
	var coins []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		coins = append(coins, Denomination(i)%NumDenominations)

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Compound.GetCoins: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		newCoins := compound.GetCoins()

		if !reflect.DeepEqual(coins, newCoins) {
			t.Errorf("Compound.GetCoins: Coins returned do"+
				" not match those passed: Passed: %v, Returned: %v", coins,
				newCoins)
		}

	}
}

// Smoke Test of Compound.GetNumCoins, it calls the underlying value function which is fully tested
func TestCompound_GetNumCoins(t *testing.T) {
	var coins []Denomination

	for i := uint64(0); i < MaxCoinsPerCompound; i++ {
		coins = append(coins, Denomination(i)%NumDenominations)

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Compound.GetCoins: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		numCoins := compound.GetNumCoins()

		if numCoins != uint64(len(coins)) {
			t.Errorf("Compound.GetNumCoins: Incorrect number of coins"+
				" returned: Passed: %v, Returned: %v", len(coins),
				numCoins)
		}

	}
}

// Smoke Test of Compound.Value, it calls the underlying value function which is fully tested
func TestCompound_Value(t *testing.T) {
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

// Shows that verify only returns true when the seed and compound match
func TestCompound_Verify(t *testing.T) {
	numInTest := 20

	src := rand.NewSource(42)
	rng := rand.New(src)

	seedLst := make([]Seed, numInTest)
	compoundLst := make([]Compound, numInTest)

	var err error

	for i := 0; i < numInTest; i++ {
		numCoins := Denomination(rng.Uint64() % MaxCoinsPerCompound)
		var coins []Denomination

		for j := Denomination(0); j < numCoins; j++ {
			coins = append(coins, Denomination(rng.Uint64()%uint64(NilDenomination)))
		}

		seedLst[i], err = NewSeed(coins)

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
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		coins = []Denomination{}

		numCoins := (rng.Uint64() % (MaxCoinsPerCompound - 1)) + 1

		for i := uint64(0); i < numCoins; i++ {
			coin := Denomination(rng.Uint64() % uint64(NilDenomination))
			coins = append(coins, coin)
		}

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Compound.Value: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		coinLst := compound.ComputeCoins()

		for indx, coin := range coinLst {
			if coin.GetDenomination() != coins[indx] {
				t.Errorf("Compound.ComputeCoins: coin denomination did not match: Expected: %v, Recieved: %v",
					coin.GetDenomination(), coins[indx])
			}
		}
	}
}

//Shows that coins differ with different inputs
func TestCompound_ComputeCoins_Randomness(t *testing.T) {
	var coins []Denomination

	src := rand.NewSource(42)
	rng := rand.New(src)

	var coinSuperList [][]Coin

	for i := 0; i < 20; i++ {
		coins = []Denomination{}

		numCoins := (rng.Uint64() % (MaxCoinsPerCompound - 1)) + 1

		for i := uint64(0); i < numCoins; i++ {
			coin := Denomination(rng.Uint64() % uint64(NilDenomination))
			coins = append(coins, coin)
		}

		seed, err := NewSeed(coins)

		if err != nil {
			t.Errorf("Compound.Value: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		coinLst := compound.ComputeCoins()

		coinSuperList = append(coinSuperList, coinLst)

		for indx, coin := range coinLst {
			if coin.GetDenomination() != coins[indx] {
				t.Errorf("Compound.ComputeCoins: coin denomination did not match: Expected: %v, Recieved: %v",
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
