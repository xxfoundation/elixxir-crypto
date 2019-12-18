////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"bytes"
	"encoding/gob"
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

		seedCopy := cs.Seed()

		if !reflect.DeepEqual(seed, *seedCopy) {
			t.Errorf("Sleeve.Seed: returned seed not equal to passed seed; Passed: %v, Expected: %v",
				seed, *seedCopy)
		}

	}
}

//Tests that the returned seed is nil when there is no seed
func TestSleeve_Seed_Nil(t *testing.T) {

	s := Sleeve{nil, nil, 0}

	if s.Seed() != nil {
		t.Errorf("Sleeve.Seed: returned a seed when it should be nil")
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

		compoundCopy := cs.Compound()

		if !reflect.DeepEqual(compound, *compoundCopy) {
			t.Errorf("Sleeve.Seed: returned compound not equal to passed compound; Passed: %v, Expected: %v",
				compound, *compoundCopy)
		}
	}
}

//Tests that the returned compound is nil when there is no seed
func TestSleeve_Compound_Nil(t *testing.T) {

	s := Sleeve{nil, nil, 0}

	if s.Compound() != nil {
		t.Errorf("Sleeve.Compound: returned a compound when it should be nil")
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

//Tests that IsNil returns the correct result for all configurations
func TestSleeve_IsNil(t *testing.T) {
	cs00 := Sleeve{nil, nil, 0}

	if !cs00.IsNil() {
		t.Errorf("Sleeve.IsNil: did not return nil when nil: %v", cs00)
	}

	cs01 := Sleeve{nil, &Compound{}, 0}

	if cs01.IsNil() {
		t.Errorf("Sleeve.IsNil: return nill when not nil: %v", cs01)
	}

	cs10 := Sleeve{&Seed{}, nil, 0}

	if cs10.IsNil() {
		t.Errorf("Sleeve.IsNil: return nill when not nil: %v", cs10)
	}

	cs11 := Sleeve{&Seed{}, &Compound{}, 0}

	if cs11.IsNil() {
		t.Errorf("Sleeve.IsNil: return nill when not nil: %v", cs11)
	}

}

//Tests that encoding and decoding work
func TestSleeve_GobEncodeDecode_NoGob(t *testing.T) {

	s, err := NewSleeve(10)

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve creation: %s", err.Error())
	}

	g, err := (&s).GobEncode()

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve encode: %s", err.Error())
	}

	sNew := &Sleeve{}

	err = sNew.GobDecode(g)

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve decode: %s", err.Error())
	}

	if !reflect.DeepEqual(s, *sNew) {
		t.Errorf("Sleeve.Encode/Decode: output sleeve difrent from input sleeve: input %v, output: %v", s, *sNew)
	}
}

//Tests that encoding and decoding works when the elements on the sleeve are nil
func TestSleeve_GobEncodeDecode_NoGob_Nil(t *testing.T) {

	s := Sleeve{nil, nil, 0}

	g, err := (&s).GobEncode()

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve encode: %s", err.Error())
	}

	sNew := &Sleeve{}

	err = sNew.GobDecode(g)

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve decode: %s", err.Error())
	}

	if !reflect.DeepEqual(s, *sNew) {
		t.Errorf("Sleeve.Encode/Decode: output sleeve diffrent from input sleeve: input %v, output: %v", s, *sNew)
	}
}

//Tests that gobbing of sleeves works
func TestSleeve_GobEncodeDecode_Gob(t *testing.T) {
	s, err := NewSleeve(10)

	if err != nil {
		t.Errorf("Sleeve.Encode/Decode: returned error on sleeve creation: %s", err.Error())
	}

	gobIO := bytes.NewBuffer([]byte{})

	enc := gob.NewEncoder(gobIO)
	dec := gob.NewDecoder(gobIO)

	err = enc.Encode(&s)

	if err != nil {
		if err != nil {
			t.Errorf("Sleeve.Encode: returned error on encoding: %s", err.Error())
		}
	}

	var sNew Sleeve

	err = dec.Decode(&sNew)

	if err != nil {
		if err != nil {
			t.Errorf("Sleeve.Encode: returned error on decoding: %s", err.Error())
		}
	}

	if !reflect.DeepEqual(s, sNew) {
		t.Errorf("Sleeve.Encode/Decode: output sleeve diffrent from input sleeve: input %v, output: %v", s, sNew)
	}
}

//Tests that gob decode errors out when the input is the wrong length
func TestSleeve_GobDecode_Length(t *testing.T) {

	sPtr := &Sleeve{}

	tooShort := make([]byte, GobLen-1)

	err := sPtr.GobDecode(tooShort)

	if err != ErrIncorrectLen {
		t.Errorf("Sleeve.Decode: did not error out with too short of input")

	}

	tooLong := make([]byte, GobLen+1)

	err = sPtr.GobDecode(tooLong)

	if err != ErrIncorrectLen {
		t.Errorf("Sleeve.Decode: did not error out with too long of input")

	}
}
