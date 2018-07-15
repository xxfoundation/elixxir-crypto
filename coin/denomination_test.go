package coin

import (
	"math/rand"
	"reflect"
	"testing"
)

// Tests the function that returns the value of denominations fails with
// denominations greater than 63
func TestDenomination_ValueTooBig(t *testing.T) {
	d := Denomination(64)

	if d.Value() != 0 {
		t.Errorf("Denomination.Value: Did not zero the output with too large"+
			" of values; Expected: 0, Received: %v+", d.Value())
	}
}

// Tests that all denominations return the correct value
func TestDenomination_ValueAllInputs(t *testing.T) {
	expectedOutputs := []uint64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
		2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576,
		2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728,
		268435456, 536870912, 1073741824, 2147483648}

	for d := Denomination(0); d < Denomination(32); d++ {
		if d.Value() != expectedOutputs[d] {
			t.Errorf("Denomination.Value: Denomination %v's value does"+
				" not match expected value: Expected: %v, Received: %v",
				d, expectedOutputs[d], d.Value())
		}
	}
}

//Tests MinMax values for DenominationRegisters
func TestNewDenominationRegister_MinMax(t *testing.T) {

	tst := make([]byte, DenominationRegisterLen)

	_, err := NewDenominationRegister(tst, 0)

	if err == nil {
		t.Errorf("NewDenominationRegister: passed an " +
			"invalud value of 0 but no error returned")
	}

	_, err = NewDenominationRegister(tst, 1<<NumDenominations)

	if err == nil {
		t.Errorf("NewDenominationRegister: passed an " +
			"invalud value of 2^16 but no error returned")
	}
}

//Tests random happy path input values for DenominationRegisters
func TestNewDenominationRegister_RandomValues(t *testing.T) {

	tst := make([]byte, DenominationRegisterLen)

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		expectedValue := rng.Uint64() % MaxValueDenominationRegister
		dr, err := NewDenominationRegister(tst, expectedValue)

		if err != nil {
			t.Errorf("NewDenominationRegister: error returned with valid"+
				"consruction: %s", err.Error())
		}

		deconstructed := uint64(dr[0]) | (uint64(dr[1]) << 8) | (uint64(dr[2]) << 16)

		if deconstructed != expectedValue {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"Expected: %v Recieved: %v", expectedValue, deconstructed)
		}
	}
}

//Tests that NewDenominationRegister returns correct errors for invalid lengths
func TestNewDenominationRegister_IncorrectLength(t *testing.T) {

	tst := make([]byte, DenominationRegisterLen+1)

	_, err := NewDenominationRegister(tst, 1)

	if err != ErrIncorrectLen {
		if err != nil {
			t.Errorf("NewDenominationRegister: Incorrect return, " +
				"no error for too long byte slice")
		} else {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"incorrect error for too long byte slice %s", err.Error())
		}
	}

	tst = make([]byte, DenominationRegisterLen-1)

	_, err = NewDenominationRegister(tst, 1)

	if err != ErrIncorrectLen {
		if err != nil {
			t.Errorf("NewDenominationRegister: Incorrect return, " +
				"no error for too short byte slice")
		} else {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"incorrect error for too short byte slice %s", err.Error())
		}
	}
}

//Tests that DeserializeDenominationRegister returns an error for incorrect lengths
func TestDeserializeDenominationRegister_Happy(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		expectedValue := rng.Uint64() % MaxValueDenominationRegister

		serialized := []byte{byte(expectedValue & 0x00ff), byte((expectedValue >> 8) & 0x00ff),
			byte((expectedValue >> 16) & 0x00ff)}

		dr, err := DeserializeDenominationRegister(serialized)

		if err != nil {
			t.Errorf("NewDenominationRegister: error returned with valid"+
				"consruction: %s", err.Error())
		}

		if !reflect.DeepEqual([]byte(dr[:]), serialized) {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"Expected: %v Recieved: %v", serialized, dr[:])
		}
	}
}

//Tests that DeserializeDenominationRegister returns correct values for randomized inputs
func TestDeserializeDenominationRegister_IncorrectLength(t *testing.T) {

	tst := make([]byte, DenominationRegisterLen+1)

	_, err := DeserializeDenominationRegister(tst)

	if err != ErrIncorrectLen {
		if err != nil {
			t.Errorf("NewDenominationRegister: Incorrect return, " +
				"no error for too long byte slice")
		} else {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"incorrect error for too long byte slice %s", err.Error())
		}
	}

	tst = make([]byte, DenominationRegisterLen-1)

	_, err = DeserializeDenominationRegister(tst)

	if err != ErrIncorrectLen {
		if err != nil {
			t.Errorf("NewDenominationRegister: Incorrect return, " +
				"no error for too short byte slice")
		} else {
			t.Errorf("NewDenominationRegister: Incorrect return, "+
				"incorrect error for too short byte slice %s", err.Error())
		}
	}
}

//Tests DenominationRegister.Bitstate Exhaustively
func TestDenominationRegister_BitState(t *testing.T) {
	dr := DenominationRegister([]byte{0, 0, 0})

	for i := uint64(0); i < NumDenominations; i++ {
		for j := uint64(0); j < DenominationRegisterLen; j++ {
			dr[j] = 0
		}

		dr[i/8] = 1 << (i % 8)

		if !dr.BitState(uint8(i)) {
			t.Errorf("DenominationRegister.BitState: Incorrect return, "+
				"on bit %v, Expected: %v Recieved: %v", i, true, false)
		}

		for j := uint64(0); j < DenominationRegisterLen; j++ {
			dr[j] = 0xff
		}

		dr[i/8] = 0xff ^ (1 << (i % 8))

		if dr.BitState(uint8(i)) {
			t.Errorf("DenominationRegister.BitState: Incorrect return, "+
				"on bit %v, Expected: %v Recieved: %v", i, false, true)
		}
	}
}

//Tests DenominationRegister.GetDenominationList
func TestDenominationRegister_GetDenominationList(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	tst := make([]byte, DenominationRegisterLen)

	for i := 0; i < 100; i++ {
		value := rng.Uint64() % MaxValueDenominationRegister

		var expectedDenomLst []Denomination

		for i := uint64(0); i < NumDenominations; i++ {
			if (value>>i)&0x00000001 == 1 {
				expectedDenomLst = append(expectedDenomLst, Denomination(i))
			}
		}

		dr, err := NewDenominationRegister(tst, value)

		if err != nil {
			t.Errorf("DenominationRegister.GetDenominationList: error "+
				"returned on DenominationRegister creation with vaild creator"+
				": %s", err.Error())
		}

		dl := dr.GetDenominationList()

		if !reflect.DeepEqual(dl, expectedDenomLst) {
			t.Errorf("DenominationRegister.GetDenominationList: returned "+
				"Denomination Listed for value %v not equal to expected, Expected %v,"+
				"Returned: %v", value, expectedDenomLst, dl)
		}
	}
}

//Tests DenominationRegister.Value
func TestDenominationRegister_Value(t *testing.T) {
	tst := make([]byte, DenominationRegisterLen)

	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 100; i++ {
		value := rng.Uint64() % MaxValueDenominationRegister

		dr, err := NewDenominationRegister(tst, value)

		if err != nil {
			t.Errorf("DenominationRegister.GetValue: error "+
				"returned on DenominationRegister creation with vaild creator"+
				": %s", err.Error())
		}

		if dr.Value() != value {
			t.Errorf("DenominationRegister.GetValue: returned "+
				"incorrect value, Expected %v,"+
				"Returned: %v", value, dr.Value())
		}
	}
}
