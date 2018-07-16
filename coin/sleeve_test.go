package coin

import (
	"math/rand"
	"reflect"
	"testing"
)

// Tests the minimum and maximum inputs to coinSleeve
func TestNewSleeve_MinMax(t *testing.T) {

	_, err := NewSleeve(0)

	if err != ErrInvalidValue {
		t.Errorf("NewCoinSleeve: No error returned when too small value of 0 passed to new coin sleeve")
	}

	_, err = NewSleeve(MaxValueDenominationRegister + 1)

	if err != ErrInvalidValue {
		t.Errorf("NewCoinSleeve: No error returned when too large value of %v passed to new coin sleeve",
			MaxValueDenominationRegister+1)
	}

	valueTestNewSleeve(1, "NewCoinSleeve", t)
	valueTestNewSleeve(MaxValueDenominationRegister, "NewCoinSleeve", t)

}

// Tests happy path of NewSleeve for random inputs
func TestNewSleeve_happy(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)
		valueTestNewSleeve(expectedValue, "NewCoinSleeve", t)
	}

}

func valueTestNewSleeve(value uint64, function string, t *testing.T) {
	cs, err := NewSleeve(value)

	if err != nil {
		t.Errorf("%s: Error returned when value of %v passed to new coin sleeve", function, value)
	}

	if cs.value != value {
		t.Errorf("%s: Incorrect value storage when value of %v passed to new coin sleeve"+
			"Expected: %v, Recieved: %v", function, value, value, cs.value)
	}

	if cs.seed.Value() != value {
		t.Errorf("%s: Value on generated seed is %v, does not match passed value of %v",
			function, cs.seed.Value(), value)
	}

	if cs.compound.Value() != value {
		t.Errorf("%s: Value on generated compound is %v, does not match passed value of %v",
			function, cs.compound.Value(), value)
	}
}

//Tests input variations of ConstructSleeve
func TestConstructSleeve_Inputs(t *testing.T) {
	// Nill Seed
	cs := ConstructSleeve(nil, &Compound{})
	if cs.seed != nil {
		t.Errorf("ConstructSleeve: Stored seed in sleeve not nill with nill input seed")
	}

	seed, _ := NewSeed(10)

	cs = ConstructSleeve(&seed, nil)

	if !reflect.DeepEqual(seed, *cs.seed) {
		t.Errorf("ConstructSleeve: passed seed does not match resulting seed")
	}

	seed, _ = NewSeed(10)

	compound := seed.ComputeCompound()

	cs = ConstructSleeve(&seed, &compound)

	if !reflect.DeepEqual(seed, *cs.seed) {
		t.Errorf("ConstructSleeve: passed seed does not match resulting seed")
	}

	if !reflect.DeepEqual(compound, *cs.compound) {
		t.Errorf("ConstructSleeve: passed compound does not match resulting compound")
	}

	seed, _ = NewSeed(10)

	compound = seed.ComputeCompound()

	cs = ConstructSleeve(nil, &compound)

	if !reflect.DeepEqual(compound, *cs.compound) {
		t.Errorf("ConstructSleeve: passed compound does not match resulting compound")
	}
}

//tests both outputs for mine
func TestSleeve_Mine(t *testing.T) {
	cs := ConstructSleeve(nil, &Compound{})

	if cs.IsMine() != false {
		t.Errorf("Sleeve.Mine: Returned false when Mine should be true")
	}

	cs = ConstructSleeve(&Seed{}, &Compound{})

	if cs.IsMine() != true {
		t.Errorf("Sleeve.Mine: Returned true when Mine should be false")
	}
}

//Tests that the returned seed is equal to the input seed in Sleeve.Seed()
func TestSleeve_Seed(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Sleeve.Seed: returned error on seed creation: %s", err.Error())
		}

		cs := ConstructSleeve(&seed, nil)

		if !reflect.DeepEqual(seed, cs.Seed()) {
			t.Errorf("Sleeve.Seed: returned seed not equal to passed seed; Passed: %v, Expected: %v",
				seed, cs.Seed())
		}

	}
}

//Tests that the returned compound is equal to the input compound in Sleeve.Compound()
func TestSleeve_Compound(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		seed, err := NewSeed(expectedValue)

		if err != nil {
			t.Errorf("Sleeve.Seed: returned error on seed creation: %s", err.Error())
		}

		compound := seed.ComputeCompound()

		cs := ConstructSleeve(&seed, &compound)

		if !reflect.DeepEqual(compound, cs.Compound()) {
			t.Errorf("Sleeve.Seed: returned compound not equal to passed compound; Passed: %v, Expected: %v",
				compound, cs.Compound())
		}
	}
}

//Tests that value returns the correctly
func TestSleeve_Value(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {

		expectedValue := rng.Uint64() % uint64(MaxValueDenominationRegister)

		cs, err := NewSleeve(expectedValue)

		if err != nil {
			t.Errorf("Sleeve.Value: returned error on sleeve creation: %s", err.Error())
		}

		if expectedValue != cs.Value() {
			t.Errorf("Sleeve.Value: returned value incorrect for NewSeed; Passed: %v, Expected: %v",
				expectedValue, cs.value)
		}

		expectedValue = rng.Uint64() % uint64(MaxValueDenominationRegister)
	}
}
