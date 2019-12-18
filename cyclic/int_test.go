////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"bytes"
	"encoding/gob"
	"errors"
	"gitlab.com/elixxir/crypto/large"
	"reflect"
	"testing"
)

var p = large.NewInt(1000000010101111111)
var g = large.NewInt(5)
var grp = NewGroup(p, g)

// Test largeInt getter and show it returns a copy
func TestGetLargeInt(t *testing.T) {
	expected := large.NewInt(42)

	actual := grp.NewInt(42)

	if actual.GetLargeInt().Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, expected: '%v', got: '%v'",
			actual.GetLargeInt(), expected)
	}

	li := actual.GetLargeInt()

	li.SetInt64(33)

	if actual.GetLargeInt().Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, did not create deep copy")
	}

}

// Test group fingeprint getter
func TestGetGroupFingerprint(t *testing.T) {

	expected := grp.GetFingerprint()

	actual := grp.NewInt(int64(42))

	if actual.GetGroupFingerprint() != expected {
		t.Errorf("Test of GetGroupFingerprint failed, expected: '%v', got: '%v'",
			actual.GetGroupFingerprint(), expected)
	}
}

// Test bytes getter
func TestBytes(t *testing.T) {
	expected := []byte{0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.Bytes(), expected) {
		t.Errorf("Test of Bytes failed, expected: '%v', got: '%v'",
			actual.Bytes(), expected)
	}
}

// Test left padded bytes getter
func TestLeftpadBytes(t *testing.T) {
	expected := []byte{0x00, 0x00, 0x00, 0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.LeftpadBytes(4), expected) {
		t.Errorf("Test of LeftPadBytes failed, expected: '%v', got: '%v'",
			actual.LeftpadBytes(4), expected)
	}
}

//TestBitLen checks if BitLen works
func TestBitLen(t *testing.T) {
	testints := []*Int{
		grp.NewInt(42),
		grp.NewInt(6553522),
		grp.NewInt(7777),
		grp.NewInt(21234)}

	expectedlens := []int{
		6,
		23,
		13,
		15}

	for i, tsti := range testints {
		actual := tsti.BitLen()
		if actual != expectedlens[i] {
			t.Errorf("Case %v of BitLen failed, got: '%v', expected: '%v'", i, actual,
				expectedlens[i])
		}
	}
}

// Tests that the copy returned by deep copy is identical and that editing
// one does not edit the other
func TestInt_DeepCopy(t *testing.T) {
	i := grp.NewInt(55)

	cpy := i.DeepCopy()

	if !reflect.DeepEqual(i, cpy) {
		t.Errorf("Test of DeepCopy failed, fingerprints did not match "+
			"expected: '%#v', got: '%#v'", i, cpy)
	}

	cpy.fingerprint = ^cpy.fingerprint

	cpy.value.SetInt64(42)

	if i.fingerprint == cpy.fingerprint {
		t.Errorf("Test of DeepCopy failed, fingerprints matched after edit "+
			"expected: '%#v', got: '%#v'", i.fingerprint, cpy.fingerprint)
	}

	if reflect.DeepEqual(i.value, cpy.value) {
		t.Errorf("Test of DeepCopy failed, values matched after edit"+
			"expected: '%#v', got: '%#v'", i.value.Text(16), cpy.value.Text(16))
	}
}

// Test that Cmp works, and that it returns -2 when fingerprints differ
func TestCmp(t *testing.T) {
	val1 := grp.NewInt(int64(42))
	val2 := grp.NewInt(int64(42))

	ret := val1.Cmp(val2)

	if ret != 0 {
		t.Errorf("Test of Cmp failed, expected: 0, "+
			"got: '%v'", ret)
	}
	// Overwrite group fingerprint and confirm Cmp returns -1
	val2.fingerprint = uint64(1234)

	ret = val1.Cmp(val2)

	if ret != -2 {
		t.Errorf("Test of Cmp failed, expected: -2, "+
			"got: '%v'", ret)
	}
}

// Test that Clear works by setting value to 1
func TestReset(t *testing.T) {
	actual := grp.NewInt(42)
	expected := large.NewInt(42)

	// Verify proper initialization to expected
	if actual.value.Cmp(expected) != 0 {
		t.Errorf("Value not initialized correctly")
	}

	// Call reset on cyclic Int
	actual.Reset()
	expected = large.NewInt(1)

	// Ensure it is equal to 1
	if actual.value.Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, expected: '%v', got: '%v'",
			actual.GetLargeInt(), expected)
	}
}

// Test text representation (limited to length of 10)
func TestText(t *testing.T) {
	testints := []*Int{
		grp.NewInt(42),
		grp.NewInt(6553522),
		grp.NewIntFromString("8675309182", 10),
		grp.NewInt(43)}
	expectedstrs := []string{
		"42 in GRP: ln9lzlk21/...",
		"6553522 in GRP: ln9lzlk21/...",
		"8675309182 in GRP: ln9lzlk21/...",
		"43 in GRP: ln9lzlk21/..."} // TODO: Should be <nil>, not -42

	for i, tsti := range testints {
		actual := tsti.Text(10)
		expected := expectedstrs[i]
		if actual != expected {
			t.Errorf("Test of Text failed, got: '%v', expected: '%v'", actual,
				expected)
		}
	}
}

// Test text verbose representation with different lengths
func TestTextVerbose(t *testing.T) {
	p_t := large.NewIntFromString("867530918239450598372829049587118723612836", 10)
	g_t := large.NewInt(5)
	group := NewGroup(p_t, g_t)

	testInt := group.NewIntFromString("867530918239450598372829049587", 10)
	lens := []int{3, 12, 16, 18, 0}
	expected := []string{
		"867... in GRP: XND...",
		"867530918239... in GRP: XNDDRA8PF/4=",
		"8675309182394505... in GRP: XNDDRA8PF/4=",
		"867530918239450598... in GRP: XNDDRA8PF/4=",
		"867530918239450598372829049587 in GRP: XNDDRA8PF/4="}

	for i, testLen := range lens {
		actual := testInt.TextVerbose(10, testLen)
		if actual != expected[i] {
			t.Errorf("Test of TextVerbose failed, got: %v,"+
				"expected: %v", actual, expected[i])
		}
	}
}

//TestByteLen checks if the ByteLen placeholder exists
func TestByteLen(t *testing.T) {
	testints := []*Int{
		grp.NewInt(1),       //1 bits -->  1 byte   (where +7 works)
		grp.NewInt(8388608), //24 bits --> 3 bytes  (exactly)
		grp.NewInt(7777),    //13 bits --> 2 bytes  (where +3 works)
		grp.NewInt(1002),    //10 bits --> 2 bytes  (where +6 works)
	}

	expectedlens := []int{
		1,
		3,
		2,
		2,
	}

	for i, tsti := range testints {
		actual := tsti.ByteLen()
		if actual != expectedlens[i] {
			t.Errorf("Case %v of ByteLen failed, got: '%v', expected: '%v'", i, actual,
				expectedlens[i])
		}
	}
}

// Test GOB encoding/decoding
func TestGob(t *testing.T) {
	var byteBuf bytes.Buffer

	enc := gob.NewEncoder(&byteBuf)
	dec := gob.NewDecoder(&byteBuf)

	inInt := grp.NewInt(42)

	err := enc.Encode(inInt)

	if err != nil {
		t.Errorf("Error GOB Encoding Int: %s", err)
	}

	outInt := grp.NewInt(1)

	err = dec.Decode(&outInt)

	if err != nil {
		t.Errorf("Error GOB Decoding Int: %s", err)
	}

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("GobEncoder/GobDecoder failed, "+
			"Expected: %v; Recieved: %v ",
			inInt.TextVerbose(10, 12),
			outInt.TextVerbose(10, 12))
	}
}

// Tests that GobDecode() for cyclicInt throws an error for a
// malformed byte array
func TestGobDecode_Error(t *testing.T) {
	inInt := Int{}
	err := inInt.GobDecode([]byte{})

	if !reflect.DeepEqual(err, errors.New("EOF")) {
		t.Errorf("GobDecode() did not produce the expected error\n\treceived: %v"+
			"\n\texpected: %v", err, errors.New("EOF"))
	}
}

// Tests that Erase() removes all underlying data from the Int.
func TestInt_Erase(t *testing.T) {
	cycInt := grp.NewInt(42)
	zeroInt := large.NewInt(5).SetInt64(0)
	cycInt.Erase()

	if !reflect.DeepEqual(cycInt.value, zeroInt) {
		t.Errorf("Erase() did not properly delete Int's underlying value"+
			"\n\treceived: %#v\n\texpected: %#v",
			cycInt.value, zeroInt)
	}

	if cycInt.fingerprint != 0 {
		t.Errorf("Erase() did not properly delete Int's underlying fingerprint"+
			"\n\treceived: %#v\n\texpected: %#v",
			cycInt.fingerprint, 0)
	}
}
