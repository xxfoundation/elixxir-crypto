////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

//TestNewInt checks if the NewInt function returns a cyclic Int with
//the same value of the passed int64
func TestNewInt(t *testing.T) {
	tests := 1

	pass := 0

	expected := big.NewInt(int64(42))

	actual := NewInt(int64(42))

	actualData := actual.Int64()
	expectedData := expected.Int64()

	if actualData != expectedData {
		t.Errorf("Test of NewInt failed, expected: '%v', got: '%v'",
			actualData, expectedData)
	} else {
		pass++
	}

	println("NewInt()", pass, "out of", tests, "tests passed.")

}

// TestNewIntFromBytes makes sure that we can get the same byte string
// out of a new Int that we put into it
func TestNewIntFromBytes(t *testing.T) {
	tests := 1

	pass := 0

	expected := []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

	cyclicInt := NewIntFromBytes(expected)

	actual := cyclicInt.value.Bytes()

	testOK := true
	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			testOK = false
			t.Errorf("NewIntFromBytes failed, expected: %v, got: %v", expected[i], actual[i])
		}
	}

	if testOK {
		pass++
	}

	println("NewIntFromBytes()", pass, "out of", tests, "tests passed.")
}

// TestNewIntFromString ensures that we get the same character string
// out of a new Int that we put into it
func TestNewIntFromString(t *testing.T) {
	tests := 2

	pass := 0

	expected := []string{"178567423", "deadbeef"}

	cyclicInts := []*Int{NewIntFromString(expected[0], 10),
		NewIntFromString(expected[1], 16)}

	actual := []string{cyclicInts[0].Text(10), cyclicInts[1].Text(16)}

	for i := 0; i < len(expected); i++ {
		testOK := true
		if expected[i] != actual[i] {
			testOK = false
			t.Errorf("NewIntFromString failed, expected: %v, got: %v", expected[i], actual[i])
		}
		if testOK {
			pass++
		}
	}

	println("NewIntFromString()", pass, "out of", tests, "tests passed.")
}

// TestNewMaxInt ensures that NewMaxInt returns the correct value for our
// upper-bound integer
func TestNewMaxInt(t *testing.T) {
	tests := 1

	pass := 0

	expected := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	actual := NewMaxInt().Bytes()
	if !bytes.Equal(actual, expected) {
		t.Error("NewMaxInt: actual differed from expected")
	} else {
		pass++
	}

	println("NewMaxInt()", pass, "out of", tests, "tests passed.")
}

// TestNewIntFromUInt makes sure that we can get the same uint64
// out of a new Int that we put into it
func TestNewIntFromUInt(t *testing.T) {
	tests := 1

	pass := 0

	expected := uint64(1203785)

	actual := NewIntFromUInt(expected).value.Uint64()

	if actual != expected {
		t.Error("NewIntFromUInt: expected", expected,
			"got", actual)
	} else {
		pass++
	}

	println("NewIntFromUInt()", pass, "out of", tests, "tests passed.")
}

//TestSet checks if the copied Int is the same as the original
func TestSet(t *testing.T) {
	tests := 1

	pass := 0

	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	actual.Set(expected)

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of Set failed, expected: '0', got: '%v'",
			result)
	} else {
		pass++
	}

	println("Set()", pass, "out of", tests, "tests passed.")
}

// Checks whether you can set an Int correctly with an int64
func TestSetInt64(t *testing.T) {
	tests := 1

	pass := 0

	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	actual.SetInt64(expected.Int64())

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of SetInt64 failed, expected: '0', got: '%v'",
			result)
	} else {
		pass++
	}

	println("SetInt64()", pass, "out of", tests, "tests passed.")
}

// Checks whether you can set an Int correctly with a uint64
func TestSetUint64(t *testing.T) {
	tests := 1

	pass := 0

	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	actual.SetUint64(expected.Uint64())

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of SetUint64 failed, expected: '0', got: '%v'",
			result)
	} else {
		pass++
	}

	println("SetUint64()", pass, "out of", tests, "tests passed.")
}

//TestSetString
func TestSetString(t *testing.T) {
	type testStructure struct {
		str  string
		base int
	}

	testStructs := []testStructure{
		{"42", 0},
		{"100000000", 0},
		{"-5", 0},
		{"0", 0},
		{"f", 0},
		{"182", 5},
		{"9000000000000000000000000000000090090909090909090090909090909090", 0},
		{"-1", 2},
	}

	tests := len(testStructs)
	pass := 0

	for i, testi := range testStructs {
		b := big.NewInt(0)
		b, eSuccess := b.SetString(testi.str, testi.base)

		// Test invalid input
		if eSuccess == false {
			actual := NewInt(0)
			actual, aSuccess := actual.SetString(testi.str, testi.base)
			if aSuccess != eSuccess || actual != nil {
				t.Error("Test of SetString() failed at index:", i,
					"Function didn't handle invalid input correctly")
			} else {
				pass++
			}
		} else {

			// Test valid input
			expected := cycInt(b)

			actual := NewInt(0)
			actual, aSuccess := actual.SetString(testi.str, testi.base)

			if actual.Cmp(expected) != 0 {
				t.Errorf("Test of SetString() failed at index: %v Expected: %v, %v;"+
					" Actual: %v, %v", i, expected, eSuccess, actual, aSuccess)
			} else {
				pass++
			}
		}
	}
	println("SetString()", pass, "out of", tests, "tests passed.")
}

func TestSetBigInt(t *testing.T) {
	expected := []*Int{
		NewInt(42),
		NewInt(6553522),
		NewIntFromString("867530918239450598372829049587", 10),
		NewInt(0)}
	testInts := []*big.Int{
		big.NewInt(42),
		big.NewInt(6553522),
		big.NewInt(1),
		big.NewInt(0),
	}
	testInts[2].SetString("867530918239450598372829049587", 10)

	actual := NewInt(0)
	for i := range testInts {
		actual.SetBigInt(testInts[i])
		if expected[i].Cmp(actual) != 0 {
			t.Errorf("Test of SetBigInt() failed at index %v."+
				"Expected %v, got %v.",
				i, expected[i].Text(10), actual.Text(10))
		}

	}
}

//TestSetBytes
func TestSetBytes(t *testing.T) {
	expected := []*Int{
		NewInt(42),
		NewInt(6553522),
		NewIntFromString("867530918239450598372829049587", 10),
		NewInt(0)}
	testBytes := [][]byte{
		{0x2A},             // 42
		{0x63, 0xFF, 0xB2}, // 6553522
		{0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20,
			0x57, 0xCE, 0xF4, 0x32, 0xF3}, //"867530918239450598372829049587",
		{0x00}}
	tests := len(expected)
	pass := 0
	actual := NewInt(0)
	for i, testi := range testBytes {
		actual = actual.SetBytes(testi)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of SetBytes failed at index %v, expected: '%v', "+
				"actual: %v", i, expected[i].Text(10), actual.Text(10))
		} else {
			pass++
		}
	}
	println("SetBytes()", pass, "out of", tests, "tests passed.")
}

//TestInt64 checks if Int64 creates an Int with the same value as the passed Int64
func TestInt64(t *testing.T) {
	tests := 1
	pass := 0

	expected := int64(42)
	actual := NewInt(int64(42)).Int64()

	if actual != expected {
		t.Errorf("Test of Int64 failed, expected: '%v', got: '%v'",
			expected, actual)
	} else {
		pass++
	}

	println("Int64()", pass, "out of", tests, "tests passed.")
}

//TestIsInt64
func TestIsInt64(t *testing.T) {
	testInts := []*Int{
		NewInt(0),
		NewInt(1000000),
		NewInt(9223372036854775807),
		NewInt(0), // int64 overflow test below
		NewInt(-1),
		NewInt(-9223372036854775808),
		NewInt(0), // int64 overflow test below
	}
	//int64 overflow tests
	success := false
	testInts[3], success = testInts[3].SetString("9223372036854775808", 10)
	if success == false {
		println("FAILED")
	}
	testInts[6], success = testInts[6].SetString("-9223372036854775809", 10)
	if success == false {
		println("FAILED")
	}
	expected := []bool{
		true,
		true,
		true,
		false,
		true,
		true,
		false,
	}
	tests := len(testInts)
	pass := 0
	for i, testi := range testInts {
		actual := testi.IsInt64()
		if actual != expected[i] {
			t.Errorf("Test of IsInt64 failed at index %v, expected: '%v', "+
				"actual: %v", i, expected[i], actual)
		} else {
			pass++
		}
	}
	println("IsInt64()", pass, "out of", tests, "tests passed.")
}

//TestMod checks if the Mod operation returns the correct result
func TestMod(t *testing.T) {

	type testStructure struct {
		x *Int
		m *Int
		r *Int
	}

	testStrings := [][]string{
		{"42", "42", "0"},
		{"42", "69", "42"},
		{"69", "42", "27"},
		{"1000000000", "11", "10"},
		{"1000000000", "9999999999999999999999", "1000000000"},
		{"9999999999999999999999", "10000", "9999"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Mod() failed at 'x' phase of index: %v", i)
		}

		ts.m, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Mod() failed at 'm' phase of index: %v", i)
		}

		ts.r, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Mod() failed at 'r' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0).Mod(testi.x, testi.m)

		result := actual.Cmp(testi.r)

		if result != expected {
			t.Errorf("Test of Mod() failed at index: %v Expected: %v, %v;"+
				" Actual: %v, %v", i, expected, testi.r.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Mod()", pass, "out of", tests, "tests passed.")

}

//TestModInverse checks if the ModInverse returns the correct result
func TestModInverse(t *testing.T) {
	type testStructure struct {
		z *Int
		m *Int
	}

	int1 := NewInt(1)

	testStrings := [][]string{
		{"3", "11"},
		{"42", "11"},
		{"100000", "15487469"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.z, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of ModInverse() failed at 'z' phase of index: %v", i)
		}

		ts.m, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of ModInverse() failed at 'm' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0).ModInverse(testi.z, testi.m)

		remultiply := NewInt(0).Mul(testi.z, actual)

		remultiply = remultiply.Mod(remultiply, testi.m)

		result := int1.Cmp(remultiply)

		if result != expected {
			t.Errorf("Test of ModInverse() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, int1.Text(10), result, remultiply.Text(10))
		} else {
			pass++
		}
	}
	println("ModInverse()", pass, "out of", tests, "tests passed.")

}

//TestAdd checks if the Add function returns correct results
func TestAdd(t *testing.T) {
	type testStructure struct {
		xint *Int
		yint *Int
		zint *Int
	}
	testCases := []testStructure{
		{NewInt(42), NewInt(69), NewInt(30)},
		{NewInt(0), NewInt(69), NewInt(0)},
		{NewInt(-50), NewInt(69), NewInt(10000)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30)},
	}

	expected := []*Int{
		NewInt(111),
		NewInt(69),
		NewInt(19),
		NewInt(0),
	}

	expected[3].SetString("9223372036854775817", 10)
	tests := len(testCases)
	pass := 0
	for i, testi := range testCases {
		actual := testi.zint.Add(testi.xint, testi.yint)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of Add() failed at index: %v Expected: %v; Actual: %v",
				i, expected[i].Text(10), actual.Text(10))
		} else {
			pass++
		}
	}
	println("Add()", pass, "out of", tests, "tests passed.")
}

//TestSub checks if the Sub function returns the correct result
func TestSub(t *testing.T) {

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "0"},
		{"42", "69", "-27"},
		{"69", "42", "27"},
		{"-69", "42", "-111"},
		{"-69", "-42", "-27"},
		{"1000000000", "1000000000", "0"},
		{"1000000000", "9999999999999999999999", "-9999999999998999999999"},
		{"9999999999999999999999", "1000000000", "9999999999998999999999"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Sub() failed at 'x' phase of index: %v", i)
		}

		ts.y, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Sub() failed at 'y' phase of index: %v", i)
		}

		ts.z, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Sub() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0).Sub(testi.x, testi.y)

		result := actual.Cmp(testi.z)

		if result != expected {
			t.Errorf("Test of Sub() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Sub()", pass, "out of", tests, "tests passed.")

}

//TestAdd checks if the Mul function returns correct results
func TestMul(t *testing.T) {
	type testStructure struct {
		xint *Int
		yint *Int
		zint *Int
	}
	testCases := []testStructure{
		{NewInt(42), NewInt(69), NewInt(30)},
		{NewInt(0), NewInt(69), NewInt(0)},
		{NewInt(-50), NewInt(69), NewInt(10000)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30)},
	}

	expected := []*Int{
		NewInt(2898),
		NewInt(0),
		NewInt(-3450),
		NewInt(0),
	}

	expected[3].SetString("92233720368547758070", 10)
	tests := len(testCases)
	pass := 0
	for i, testi := range testCases {
		actual := testi.zint.Mul(testi.xint, testi.yint)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of Mul() failed at index: %v Expected: %v; Actual: %v",
				i, expected[i].Text(10), actual.Text(10))
		} else {
			pass++
		}
	}
	println("Mul()", pass, "out of", tests, "tests passed.")
}

//TestDiv checks if the Sub function returns the correct result
func TestDiv(t *testing.T) {

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "1"},
		{"42", "-42", "-1"},
		{"42", "69", "0"},
		{"69", "42", "1"},
		{"-69", "42", "-2"},
		{"-69", "-42", "2"},
		{"1000000000", "1000000000", "1"},
		{"1000000000", "9999999999999999999999", "0"},
		{"9999999999999999999999", "1000000000", "9999999999999"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Div() failed at 'x' phase of index: %v", i)
		}

		ts.y, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Div() failed at 'y' phase of index: %v", i)
		}

		ts.z, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Div() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0).Div(testi.x, testi.y)

		result := actual.Cmp(testi.z)

		if result != expected {
			t.Errorf("Test of Div() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Div()", pass, "out of", tests, "tests passed.")

}

//TestExp checks if the Exp returns the correct results
func TestExp(t *testing.T) {

	type testStructure struct {
		x *Int
		y *Int
		m *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "11", "4"},
		{"42", "69", "31", "23"},
		{"-69", "42", "17", "1"},
		{"1000000000", "9999999", "12432332443", "6589464193"},
	}

	var testStructs []testStructure

	var sucess bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, sucess = NewInt(0).SetString(strs[0], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() failed at 'x' phase of index: %v", i)
		}

		ts.y, sucess = NewInt(0).SetString(strs[1], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() failed at 'y' phase of index: %v", i)
		}

		ts.m, sucess = NewInt(0).SetString(strs[2], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() failed at 'm' phase of index: %v", i)
		}

		ts.z, sucess = NewInt(0).SetString(strs[3], 10)

		if sucess != true {
			t.Errorf("Setup for Test of Exp() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	tests := len(testStructs)
	pass := 0

	expected := 0

	for i, testi := range testStructs {
		actual := NewInt(0).Exp(testi.x, testi.y, testi.m)

		result := actual.Cmp(testi.z)

		if result != expected {
			t.Errorf("Test of Exp() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, testi.z.Text(10), result, actual.Text(10))
		} else {
			pass += 1
		}
	}
	println("Exp()", pass, "out of", tests, "tests passed.")

}

//TestBytes checks if the Bytes placeholder exists
func TestBytes(t *testing.T) {
	testints := []Int{
		*NewInt(42),
		*NewInt(6553522),
		//*NewInt(867530918239450598372829049587), TODO: When text parsing impl
		*NewInt(-42)}
	expectedbytes := [][]byte{
		{0x2A},             // 42
		{0x63, 0xFF, 0xB2}, // 6553522
		// { 0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20,
		//   0x57, 0xCE, 0xF4, 0x32, 0xF3 }, //"867530918239450598372829049587",
		{0x2A}} // TODO: Should be <nil>, not 42
	tests := len(testints)
	pass := 0
	for i, tsti := range testints {
		actual := bigInt(&tsti).Bytes()
		for j, tstb := range expectedbytes[i] {
			if actual[j] != tstb {
				t.Errorf("Case %v of Text failed, got: '%v', expected: '%v'", i, actual,
					tstb)
			}
		}
		pass++
	}
	println("Bytes()", pass, "out of", tests, "tests passed.")
}

// TestLeftpadBytes makes sure that LeftpadBytes returns the correctly
// leftpadded byte strings
func TestLeftpadBytes(t *testing.T) {
	testInts := []*Int{
		NewInt(420),
		NewInt(6553522),
		NewInt(0),
		NewInt(-42)}

	testLengths := []uint64{
		3,
		7,
		5,
		8}
	expected := [][]byte{
		[]byte{0, 1, 164},
		[]byte{0, 0, 0, 0, 99, 255, 178},
		[]byte{0, 0, 0, 0, 0},
		[]byte{0, 0, 0, 0, 0, 0, 0, 42},
	}

	for i := range testInts {
		actual := testInts[i].LeftpadBytes(testLengths[i])
		if !bytes.Equal(actual, expected[i]) {
			t.Errorf("LeftpadBytes: Actual differed from expected at index"+
				" %v. Got %v, expected %v.", i, actual, expected[i])
		}
	}
}

//TestBitLen checks if the BitLen placeholder exists
func TestBitLen(t *testing.T) {
	testints := []*Int{
		NewInt(42),
		NewInt(6553522),
		NewInt(0),
		NewInt(-42)}

	testints[2], _ = testints[2].SetString("867530918239450598372829049587", 10)

	tests := len(testints)
	pass := 0

	expectedlens := []int{
		6,
		23,
		100,
		6}

	for i, tsti := range testints {
		actual := tsti.BitLen()
		if actual != expectedlens[i] {
			t.Errorf("Case %v of BitLen failed, got: '%v', expected: '%v'", i, actual,
				expectedlens[i])
		} else {
			pass++
		}
	}
	println("BitLen()", pass, "out of", tests, "tests passed.")
}

//TestCmp checks if the Cmp placeholder exists
func TestCmp(t *testing.T) {

	var expected, actual int
	var xint, yint *Int

	tests := 3
	pass := 0

	//Tests for case where x < y

	expected = -1

	xint = NewInt(42)
	yint = NewInt(69)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'less than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	} else {
		pass++
	}

	//Tests for case where x==y

	expected = 0

	xint = NewInt(42)
	yint = NewInt(42)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'equals' of Cmp failed, expected: '%v', got: '%v'",
			actual, expected)
	} else {
		pass++
	}

	//Test for case where x > y

	expected = 1

	xint = NewInt(69)
	yint = NewInt(42)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'greater than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	} else {
		pass++
	}

	println("Cmp()", pass, "out of", tests, "tests passed.")

}

//TestText checks if the Text placeholder exists
func TestText(t *testing.T) {
	testints := []Int{
		*NewInt(42),
		*NewInt(6553522),
		*NewIntFromString("867530918239450598372829049587", 10),
		*NewInt(-42)}
	expectedstrs := []string{
		"42",
		"6553522",
		"8675309182...",
		"-42"} // TODO: Should be <nil>, not -42
	tests := len(testints)
	pass := 0
	for i, tsti := range testints {
		actual := tsti.Text(10)
		expected := expectedstrs[i]
		if actual != expected {
			t.Errorf("Test of Text failed, got: '%v', expected: '%v'", actual,
				expected)
		} else {
			pass++
		}
	}
	println("Text()", pass, "out of", tests, "tests passed.")
}

func TestTextVerbose(t *testing.T) {
	testInt := NewIntFromString("867530918239450598372829049587", 10)
	lens := []int{12, 16, 18, 0}
	expected := []string{"867530918239...", "8675309182394505...",
		"867530918239450598...", "867530918239450598372829049587"}
	tests := len(lens)
	pass := 0
	for i, testLen := range lens {
		actual := testInt.TextVerbose(10, testLen)
		if actual != expected[i] {
			t.Errorf("Test of TextVerbose failed, got: %v,"+
				"expected: %v", actual, expected[i])
		} else {
			pass++
		}
	}
	println("TestTextVerbose()", pass, "out of", tests, "tests passed.")

}

//TestBigInt checks if the function GetBigInt returns a big.Int
func TestBigInt(t *testing.T) {

	tests := 1
	pass := 0

	expected := reflect.TypeOf(big.NewInt(int64(42)))

	actual := reflect.TypeOf(bigInt(NewInt(int64(42))))

	if actual != expected {
		t.Errorf("Test of bigInt failed, expected: '%v', got: '%v'",
			actual, expected)
	} else {
		pass++
	}

	println("bigInt()", pass, "out of", tests, "tests passed.")

}

func TestExtendedGCD(t *testing.T) {
	a := NewInt(178919)
	b := NewInt(987642)
	// These will be filled in by GCD and can calculate modular inverse
	x := NewInt(0)
	y := NewInt(0)
	// This will hold the actual GCD
	actual := NewInt(0)

	actual.GCD(x, y, a, b)

	expected := NewInt(1)

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestExtendedGCD: got %v, expected %v", actual.Text(10),
			expected.Text(10))
	}
	// use results of extended GCD to calculate modular inverse and check
	// consistency with ModInverse
	if x.Cmp(NewInt(0)) < 0 {
		// we need to add the prime in again to put the result back in the
		// cyclic group
		x.Add(x, b)
	}
	modInverseResult := NewInt(0)
	if x.Cmp(modInverseResult.ModInverse(a, b)) != 0 {
		t.Errorf("TestExtendedGCD: got incorrect modular inverse %v, "+
			"expected %v", x.Text(10), modInverseResult.Text(10))
	}
}

// Test that IsCoprime returns false when sent a 0
func TestIsCoprime0(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(0)
	if a.IsCoprime(b) {
		t.Errorf("0 cannot be Coprime!")
	}
}

// Test that IsCoprime returns true when sent a 1
func TestIsCoprime1(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(1)
	if !a.IsCoprime(b) {
		t.Errorf("1 must always be Coprime")
	}
}

// Test that IsCoprime returns true when sent a 14
func TestIsCoprime49(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(49)
	if !a.IsCoprime(b) {
		gcdAB := NewInt(0)
		gcdAB.GCD(nil, nil, a, b)
		t.Errorf("49 must always be Coprime: GCD(%d, %d) -> %d)",
			a.Int64(), b.Int64(), gcdAB.Int64())
	}
}

func TestIsPrime(t *testing.T) {
	n := NewInt(101) // 101 is prime
	if !n.IsPrime() {
		t.Errorf("IsPrime: %v should be prime!", n.Uint64())
	}

	n = NewInt(63) // 63 is NOT prime
	if n.IsPrime() {
		t.Errorf("IsPrime: %v should NOT be prime!", n.Uint64())
	}
}

func TestGob(t *testing.T) {

	var byteBuf bytes.Buffer

	enc := gob.NewEncoder(&byteBuf)
	dec := gob.NewDecoder(&byteBuf)

	inInt := NewInt(42)

	enc.Encode(inInt)

	outInt := NewInt(0)

	dec.Decode(&outInt)

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("GobEncoder/GobDecoder failed, "+
			"Expected: %v; Recieved: %v ", inInt.Text(10), outInt.Text(10))
	}

}

func TestInt_And(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		aCyclic := NewIntFromUInt(aInt)
		bCyclic := NewIntFromUInt(bInt)

		resultCyclic := NewInt(0).And(aCyclic, bCyclic)

		if resultCyclic.Uint64() != (aInt & bInt) {
			t.Errorf("CyclicInt.And: andd value not as expected: Expected: %v, Recieved: %v",
				aInt&bInt, resultCyclic.Uint64())
		}
	}
}

func TestInt_Or(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		aCyclic := NewIntFromUInt(aInt)
		bCyclic := NewIntFromUInt(bInt)

		resultCyclic := NewInt(0).Or(aCyclic, bCyclic)

		if resultCyclic.Uint64() != (aInt | bInt) {
			t.Errorf("CyclicInt.Or: ored value not as expected: Expected: %v, Recieved: %v",
				aInt|bInt, resultCyclic.Uint64())
		}
	}
}

func TestInt_Xor(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		aCyclic := NewIntFromUInt(aInt)
		bCyclic := NewIntFromUInt(bInt)

		resultCyclic := NewInt(0).Xor(aCyclic, bCyclic)

		if resultCyclic.Uint64() != (aInt ^ bInt) {
			t.Errorf("CyclicInt.Xor: xored value not as expected: Expected: %v, Recieved: %v",
				aInt^bInt, resultCyclic.Uint64())
		}
	}
}

func BenchmarkInt_Xor(b *testing.B) {
	src := rand.NewSource(42)
	rng := rand.New(src)
	var aCyclics []*Int
	var bCyclics []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 256)
		rng.Read(byteField)
		aCyclics = append(aCyclics, NewIntFromBytes(byteField))
		rng.Read(byteField)
		bCyclics = append(bCyclics, NewIntFromBytes(byteField))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewInt(0).Xor(aCyclics[i], bCyclics[i])
	}
}

func TestInt_LeftShift(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()

		shift := rng.Uint64() % 63

		aCyclic := NewIntFromUInt(aInt)

		resultCyclic := NewInt(0).LeftShift(aCyclic, uint(shift))

		if resultCyclic.Uint64() != (aInt << shift) {
			t.Errorf("CyclicInt.LeftShift: shifted value not as expected: Expected: %v, Recieved: %v",
				aInt<<shift, resultCyclic.Uint64())
		}
	}

}

func TestInt_RightShift(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()

		shift := rng.Uint64() % 63

		aCyclic := NewIntFromUInt(aInt)

		resultCyclic := NewInt(0).RightShift(aCyclic, uint(shift))

		if resultCyclic.Uint64() != (aInt >> shift) {
			t.Errorf("CyclicInt.RightShift: shifted value not as expected: Expected: %v, Recieved: %v",
				aInt>>shift, resultCyclic.Uint64())
		}
	}

}

func BenchmarkSha256(b *testing.B) {
	var strings [][]byte
	h := sha256.New()

	r := rand.New(rand.NewSource(42))
	s := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		r.Read(s)
		strings = append(strings, s)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(strings[i])
		h.Sum(nil)
	}
}
