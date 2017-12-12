package cyclic

import (
	"math/big"
	"reflect"
	"testing"
)

//TestGetBigInt checks if the function GetBigInt returns a big.Int
func TestGetBigInt(t *testing.T) {
	expected := reflect.TypeOf(big.NewInt(int64(42)))

	actual := reflect.TypeOf(BigInt(NewInt(int64(42))))

	if actual != expected {
		t.Errorf("Test of GetBigInt failed, expected: '%v', got:  '%v'", actual, expected)
	}
}

//TestNewInt checks if the NewInt function returns a cyclic Int with the same value of the passed int64
func TestNewInt(t *testing.T) {
	expected := big.NewInt(int64(42))

	actual := NewInt(int64(42))

	actualData := BigInt(actual).Int64()
	expectedData := expected.Int64()

	if actualData != expectedData {
		t.Errorf("Test of NewInt failed, expected: '%v', got:  '%v'", actualData, expectedData)
	}
}

//TestSetString checks if the SetString placeholder works
func TestSetString(t *testing.T) {
	expectedInt := nilInt()

	nint := NewInt(42)

	actualInt, actualBool := nint.SetString("42", 0)

	if actualInt != expectedInt {
		t.Errorf("Test of SetString failed, expected: '%v', got:  '%v'", actualInt, actualBool)
	}

}

//TestSetBytes checks if the SetBytes placeholder exists
func TestSetBytes(t *testing.T) {

	var buf []byte

	expected := nilInt()

	nint := NewInt(42)

	actual := nint.SetBytes(buf)

	if actual != expected {
		t.Errorf("Test of SetBytes failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestMod checks if the Mod placeholder exists
func TestMod(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)

	actual := zint.Mod(xint, yint)

	if actual != expected {
		t.Errorf("Test of Mod failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestModInverse checks if the ModInverse placeholder exists
func TestModInverse(t *testing.T) {

	expected := nilInt()

	gint := NewInt(42)
	nint := NewInt(69)
	zint := NewInt(30)

	actual := zint.ModInverse(gint, nint)

	if actual != expected {
		t.Errorf("Test of Mod failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestAdd checks if the Add placeholder exists
func TestAdd(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)

	actual := zint.Add(xint, yint)

	if actual != expected {
		t.Errorf("Test of Add failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestMul checks if the Mod placeholder exists
func TestMul(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)

	actual := zint.Mul(xint, yint)

	if actual != expected {
		t.Errorf("Test of Mul failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestExp checks if the Exp placeholder exists
func TestExp(t *testing.T) {

	expected := nilInt()

	xint := NewInt(42)
	yint := NewInt(69)
	zint := NewInt(30)
	mint := NewInt(87)

	actual := zint.Exp(xint, yint, mint)

	if actual != expected {
		t.Errorf("Test of Exp failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestBytes checks if the Bytes placeholder exists
func TestBytes(t *testing.T) {

	xint := NewInt(42)

	actual := xint.Bytes()

	if actual != nil {
		t.Errorf("Test of Bytes failed, expected: 'nil', got:  '%v'", actual)
	}

}

//TestBitLen checks if the BitLen placeholder exists
func TestBitLen(t *testing.T) {
	expected := -1

	xint := NewInt(42)

	actual := xint.BitLen()

	if actual != expected {
		t.Errorf("Test of BitLen failed, expected: '%v', got:  '%v'", actual, expected)
	}
}

//TestCmp checks if the Cmp placeholder exists
func TestCmp(t *testing.T) {

	xint := NewInt(42)
	yint := NewInt(69)

	actual := xint.Cmp(yint)

	expected := 42

	if actual != expected {
		t.Errorf("Test of Cmp failed, expected: '%v', got:  '%v'", actual, expected)
	}

}

//TestText checks if the Text placeholder exists
func TestText(t *testing.T) {

	xint := NewInt(42)
	base := 42

	actual := xint.Text(base)

	expected := ""

	if actual != expected {
		t.Errorf("Test of Text failed, expected: '%v', got:  '%v'", actual, expected)
	}

}
