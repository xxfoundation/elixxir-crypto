package cyclic

import (
	"math/big"
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
		{"10", 0},
	}

	tests := len(testStructs)
	pass := 0

	expected := NewInt(0)

	for i, testi := range testStructs {
		b := big.NewInt(0)
		b, eSuccess := b.SetString(testi.str, testi.base)
		//println(eSuccess)

		expected.SetBigInt(b)

		actual := NewInt(0)
		actual, aSuccess := actual.SetString(testi.str, testi.base)

		if actual.Cmp(expected) != 0 {
			t.Errorf("Test of SetString failed at index: %v Expected: %v, %v;",
				" Actual: %v, %v", i, expected, eSuccess, actual, aSuccess)
		} else {
			pass += 1
		}
	}
	println("SetString()", pass, "out of ", tests, "tests passed.")
}

/*/TestSetBytes
func TestSetBytes(t *testing.T) {

	var buf []byte

	expected := nilInt()

	nint := NewInt(42)

	actual := nint.SetBytes(buf)

	if actual != expected {
		t.Errorf("Test of SetBytes failed, expected: '%v', got: '%v'",
			actual, expected)
	}

}
*/

//!!!TestInt64!!!
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

//!!!TestIsInt64!!!

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
			t.Errorf("Test of Mod() failed at index: %v Expected: %v, %v;",
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
			pass += 1
		}
	}
	println("ModInverse()", pass, "out of", tests, "tests passed.")

}

//TestAdd checks if the Add placeholder exists
func TestAdd(t *testing.T) {

	var actual, expected int64
	var xint, yint, zint *Int

	xint = NewInt(42)
	yint = NewInt(69)
	zint = NewInt(30)

	expected = 111
	actual = zint.Add(xint, yint).Int64()

	if actual != expected {
		t.Errorf("Test of Add failed, expected: '%v', got:  '%v'", actual, expected)
	}

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

//TestMul checks if the Mod placeholder exists
/*func TestMul(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)

	actual := zint.Mul(xint, yint)

	if actual != expected {
		t.Errorf("Test of Mul failed, expected: '%v', got:  '%v'", actual, expected)
	}

}*/

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

	for i, tsti := range testints {
		actual := bigInt(&tsti).Bytes()
		for j, tstb := range expectedbytes[i] {
			if actual[j] != tstb {
				t.Errorf("Case %v of Text failed, got: '%v', expected: '%v'", i, actual,
					tstb)
			}
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

	testints[2].SetString("867530918239450598372829049587", 10)

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
		//*NewInt(867530918239450598372829049587), TODO: When text parsing impl
		*NewInt(-42)}
	expectedstrs := []string{
		"42",
		"6553522",
		//"867530918239450598372829049587",
		"-42"} // TODO: Should be <nil>, not -42

	for i, tsti := range testints {
		actual := tsti.Text(10)
		expected := expectedstrs[i]
		if actual != expected {
			t.Errorf("Test of Text failed, got: '%v', expected: '%v'", actual,
				expected)
		}
	}
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

///!!!TestNilInt!!!
