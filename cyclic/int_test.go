////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
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
var q = large.NewInt(1283)
var grp = NewGroup(p, g, q)

// Test largeInt getter
func TestGetLargeInt(t *testing.T) {
	tests := 1
	pass := 0

	expected := large.NewInt(42)

	actual := grp.NewInt(42)

	if actual.GetLargeInt().Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, expected: '%v', got: '%v'",
			actual.GetLargeInt(), expected)
	} else {
		pass++
	}

	println("TestGetLargeInt()", pass, "out of", tests, "tests passed.")
}

// Test group fingeprint getter
func TestGetGroupFingerprint(t *testing.T) {
	tests := 1
	pass := 0

	expected := grp.GetFingerprint()

	actual := grp.NewInt(int64(42))

	if actual.GetGroupFingerprint() != expected {
		t.Errorf("Test of GetGroupFingerprint failed, expected: '%v', got: '%v'",
			actual.GetGroupFingerprint(), expected)
	} else {
		pass++
	}

	println("TestGetGroupFingerprint()", pass, "out of", tests, "tests passed.")
}

// Test bytes getter
func TestBytes(t *testing.T) {
	tests := 1
	pass := 0

	expected := []byte{0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.Bytes(), expected) {
		t.Errorf("Test of Bytes failed, expected: '%v', got: '%v'",
			actual.Bytes(), expected)
	} else {
		pass++
	}

	println("TestBytes()", pass, "out of", tests, "tests passed.")
}

// Test left padded bytes getter
func TestLeftpadBytes(t *testing.T) {
	tests := 1
	pass := 0

	expected := []byte{0x00, 0x00, 0x00, 0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.LeftpadBytes(4), expected) {
		t.Errorf("Test of LeftPadBytes failed, expected: '%v', got: '%v'",
			actual.LeftpadBytes(4), expected)
	} else {
		pass++
	}

	println("TestLeftPadBytes()", pass, "out of", tests, "tests passed.")
}

// Tests that the copy retruned by deep copy is identical and that editing
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

// Test that Cmp works, and that it returns -1 when fingerprints differ
func TestCmp(t *testing.T) {
	tests := 2
	pass := 0

	val1 := grp.NewInt(int64(42))
	val2 := grp.NewInt(int64(42))

	ret := val1.Cmp(val2)

	if ret != 0 {
		t.Errorf("Test of Cmp failed, expected: 0, "+
			"got: '%v'", ret)
	} else {
		pass++
	}

	// Overwrite group fingerprint and confirm Cmp returns -1
	val2.fingerprint = uint64(1234)

	ret = val1.Cmp(val2)

	if ret != -1 {
		t.Errorf("Test of Cmp failed, expected: -1, "+
			"got: '%v'", ret)
	} else {
		pass++
	}

	println("TestCmp()", pass, "out of", tests, "tests passed.")
}

// Test that Clear works by setting value to 1
func TestReset(t *testing.T) {
	tests := 2
	pass := 0

	actual := grp.NewInt(42)
	expected := large.NewInt(42)

	// Verify proper initialization to expected
	if actual.value.Cmp(expected) != 0 {
		t.Errorf("Value not initialized correctly")
	} else {
		pass++
	}

	// Call reset on cyclic Int
	actual.Reset()
	expected = large.NewInt(1)

	// Ensure it is equal to 1
	if actual.value.Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, expected: '%v', got: '%v'",
			actual.GetLargeInt(), expected)
	} else {
		pass++
	}

	println("TestGetLargeInt()", pass, "out of", tests, "tests passed.")
}

// Test text representation (limited to length of 10)
func TestText(t *testing.T) {
	testints := []*Int{
		grp.NewInt(42),
		grp.NewInt(6553522),
		grp.NewIntFromString("8675309182", 10),
		grp.NewInt(43)}
	expectedstrs := []string{
		"42 in GRP: 4XgotyuZEW...",
		"6553522 in GRP: 4XgotyuZEW...",
		"8675309182 in GRP: 4XgotyuZEW...",
		"43 in GRP: 4XgotyuZEW..."} // TODO: Should be <nil>, not -42
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

// Test text verbose representation with different lengths
func TestTextVerbose(t *testing.T) {
	p_t := large.NewIntFromString("867530918239450598372829049587118723612836", 10)
	g_t := large.NewInt(5)
	q_t := large.NewInt(1283)
	group := NewGroup(p_t, g_t, q_t)

	testInt := group.NewIntFromString("867530918239450598372829049587", 10)
	lens := []int{3, 12, 16, 18, 0}
	expected := []string{
		"867... in GRP: t9A...",
		"867530918239... in GRP: t9Aiywu7oD8=",
		"8675309182394505... in GRP: t9Aiywu7oD8=",
		"867530918239450598... in GRP: t9Aiywu7oD8=",
		"867530918239450598372829049587 in GRP: t9Aiywu7oD8="}
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
