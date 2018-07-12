package coin

import (
	"testing"
	"math/rand"
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
	expectedOutputs := []uint32{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
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
	_, err := NewDenominationRegister(0)

	if err== nil{
		t.Errorf("NewDenominationRegister: passed an " +
			"invalud value of 0 but no error returned")
	}

	_, err = NewDenominationRegister(1<<NumDenominations)

	if err==nil{
		t.Errorf("NewDenominationRegister: passed an " +
			"invalud value of 2^16 but no error returned")
	}
}

//Tests random happy path input values for DenominationRegisters
func TestNewDenominationRegister_RandomValues(t *testing.T) {

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i:=0;i<100;i++{
		expectedValue := rng.Uint64()%MaxValueDenominationRegister
		dr, err := NewDenominationRegister(expectedValue)

		if err !=nil{
			t.Errorf("NewDenominationRegister: error returned with valid" +
				"consruction: %s", err.Error())
		}

		deconstructed := uint64(dr[0]) | (uint64(dr[1])<<8) | (uint64(dr[2])<<16)

		if deconstructed != expectedValue {
			t.Errorf("NewDenominationRegister: Incorrect return, " +
				"Expected: %v Recieved: %v", expectedValue, deconstructed)
		}
	}
}

//Tests DenominationRegister.Bitstate Exhaustively
func TestDenominationRegister_BitState(t *testing.T) {
	var dr DenominationRegister

	for i:=uint64(0);i<NumDenominations;i++{
		for j:=uint64(0);j<DenominationRegisterLen;j++{
			dr[j] = 0
		}

		dr[i/8] = 1<<(i%8)

		if dr.BitState(uint8(i)) ==


	}
}
