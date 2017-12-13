package cyclic

import (
	"math/big"
	"reflect"
	"testing"
)

//TestBigInt checks if the function GetBigInt returns a big.Int
func TestBigInt(t *testing.T) {
	expected := reflect.TypeOf(big.NewInt(int64(42)))

	actual := reflect.TypeOf(bigInt(NewInt(int64(42))))

	if actual != expected {
		t.Errorf("Test of GetBigInt failed, expected: '%v', got: '%v'",
			actual, expected)
	}
}

//TestNewInt checks if the NewInt function returns a cyclic Int with
//the same value of the passed int64
func TestNewInt(t *testing.T) {
	expected := big.NewInt(int64(42))

	actual := NewInt(int64(42))

	actualData := bigInt(actual).Int64()
	expectedData := expected.Int64()

	if actualData != expectedData {
		t.Errorf("Test of NewInt failed, expected: '%v', got: '%v'",
			actualData, expectedData)
	}
}


/*
//TestSetBytes checks if the SetBytes placeholder exists
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

//TestMod checks if the Mod placeholder exists
func TestMod(t *testing.T) {
	var actual, expected int64
	var xint, mint, zint *Int

	zint = NewInt(30)

	//Test where x<m

	expected = 42

	xint = NewInt(42)
	mint = NewInt(69)

	actual = zint.Mod(xint, mint).Int64()

	if actual != expected {
		t.Errorf("Test 'x<m' of Mod failed, expected: '%v', got: '%v'",
			expected, actual)
	}

	//Test where x == m
	expected = 0

	xint = NewInt(42)
	mint = NewInt(42)

	actual = zint.Mod(xint, mint).Int64()

	if actual != expected {
		t.Errorf("Test 'x==m' of Mod failed, expected: '%v', got: '%v'",
			expected, actual)
	}

	//test where x>m

	expected = 27

	xint = NewInt(69)
	mint = NewInt(42)

	actual = zint.Mod(xint, mint).Int64()

	if actual != expected {
		t.Errorf("Test 'x>m' of Mod failed, expected: '%v', got: '%v'",
			expected, actual)
	}

}

//TestModInverse checks if the ModInverse placeholder exists
func TestModInverse(t *testing.T) {

	var expected, actual int64

	expected = 69

	gint := NewInt(42)
	nint := NewInt(27)
	zint := NewInt(30)

	actual = zint.ModInverse(gint, nint).Int64()

	actual = actual * expected

	/*if actual != expected {
		t.Errorf("Test of Mod failed, expected: '%v', got:  '%v'", expected, actual)
	}*/

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

//TestExp checks if the Exp placeholder exists
/*func TestExp(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)
	mint := NewInt(87)

	actual := zint.Exp(xint, yint, mint)

	actual = actual * expected

	/*if actual != expected {
		t.Errorf("Test of Exp failed, expected: '%v', got:  '%v'", actual, expected)
	}

}*/

//TestBytes checks if the Bytes placeholder exists
/*func TestBytes(t *testing.T) {

	xint := NewInt(42)

	actual := xint.Bytes()

	actual = actual * expected

	/*if actual != nil {
		t.Errorf("Test of Bytes failed, expected: 'nil', got:  '%v'", actual)
	}

}*/

//TestBitLen checks if the BitLen placeholder exists
/*func TestBitLen(t *testing.T) {
	expected := -1

	xint := NewInt(42)

	actual := xint.BitLen()

	actual = actual * expected

	/*if actual != expected {
		t.Errorf("Test of BitLen failed, expected: '%v', got: '%v'",
			actual, expected)
	}
}*/

//TestCmp checks if the Cmp placeholder exists
//TestCmp checks if the Cmp placeholder exists
func TestCmp(t *testing.T) {

	var expected, actual int
	var xint, yint *Int

	//Tests for case where x < y

	expected = -1

	xint = NewInt(42)
	yint = NewInt(69)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'less than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	}

	//Tests for case where x==y

	expected = 0

	xint = NewInt(42)
	yint = NewInt(42)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'equals' of Cmp failed, expected: '%v', got: '%v'",
			actual, expected)
	}

	//Test for case where x > y

	expected = 1

	xint = NewInt(69)
	yint = NewInt(42)

	actual = xint.Cmp(yint)

	if actual != expected {
		t.Errorf("Test 'greater than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	}

}

//TestText checks if the Text placeholder exists
/*func TestText(t *testing.T) {

	xint := NewInt(42)
	base := 42

	actual := xint.Text(base)

	expected := ""

	actual = actual * expected

	/*if actual != expected {
		t.Errorf("Test of Text failed, expected: '%v', got: '%v'", actual,
			expected)
	}

}*/
