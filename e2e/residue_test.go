////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

// TestMakeKeyResidue the consistency of NewKeyResidue.
func TestMakeKeyResidue(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"sMweiL8iqwQ6sSvKpeNI6X75Q62PNjjtRuXwdsgdsYs=",
		"Vm9LKiZhyLTjU9CAZun0vcC3ppYrSKyv8Ve3PRPTs14=",
		"ygQoB7igwNbvAHNepSmbW36YDm3vxfE6CbmB5F4/wBQ=",
		"KcIeQV/jKvxfvVmrrlzAFPhWZR9chJv1smu+nDAdppg=",
	}

	for _, exp := range expected {
		randData := make([]byte, 32)
		prng.Read(randData)
		k := Key{}
		copy(k[:], randData)
		kr := NewKeyResidue(k)
		krString := base64.StdEncoding.EncodeToString(kr[:])
		if krString != exp {
			t.Errorf("Failed KeyResidue are not consistant\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				krString)
		}
	}
}

// TestNewKeyResidue_AllInputs tests that different inputs
// results in different output.
func TestNewKeyResidue_AllInputs(t *testing.T) {
	const NumCompares = 1000

	prng := rand.New(rand.NewSource(42))

	var keys []Key

	for i := 0; i < NumCompares; i++ {
		randData := make([]byte, 32)
		prng.Read(randData)
		k := Key{}
		copy(k[:], randData)
		keys = append(keys, k)
	}

	collisionMap := make(map[KeyResidue]struct{})

	for i := 0; i < NumCompares; i++ {
		kr := NewKeyResidue(keys[i])
		if _, ok := collisionMap[kr]; ok {
			t.Errorf("A key residue collission ws found")
		}
		collisionMap[kr] = struct{}{}

	}
}

// Tests that UnmarshalKeyResidue produces the correct result.
func TestUnmarshalKeyResidue(t *testing.T) {

	expected := []string{
		"sMweiL8iqwQ6sSvKpeNI6X75Q62PNjjtRuXwdsgdsYs=",
		"Vm9LKiZhyLTjU9CAZun0vcC3ppYrSKyv8Ve3PRPTs14=",
		"ygQoB7igwNbvAHNepSmbW36YDm3vxfE6CbmB5F4/wBQ=",
		"KcIeQV/jKvxfvVmrrlzAFPhWZR9chJv1smu+nDAdppg=",
	}

	for _, exp := range expected {

		expectedInput, _ := base64.StdEncoding.DecodeString(exp)

		mid, err := UnmarshalKeyResidue(expectedInput)
		if err != nil {
			t.Errorf("unexpected rror returned on unmarshal: %s", err)
		}
		midString := base64.StdEncoding.EncodeToString(mid[:])
		if midString != exp {
			t.Errorf("Key Residues are not consistant\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				midString)
		}
	}
}

// Tests that the wrong size error triggers correctly.
func TestUnmarshalKeyResidue_Error(t *testing.T) {
	nilKeyResidue := KeyResidue{}

	badKeyResidue, err := UnmarshalKeyResidue([]byte{69})
	if !bytes.Equal(badKeyResidue[:], nilKeyResidue[:]) {
		t.Errorf("Too small input did not return a nil key residue")
	}

	if err == nil {
		t.Errorf("No error was returned with too small input")
	} else if !strings.Contains(err.Error(), keyResidueIncorrectLenErr) {
		t.Errorf("wrong error returned when too small input: %s", err)
	}

	prng := rand.New(rand.NewSource(42))
	badBinary := make([]byte, 33)
	prng.Read(badBinary)

	badKeyResidue, err = UnmarshalKeyResidue(badBinary)
	if !bytes.Equal(badKeyResidue[:], nilKeyResidue[:]) {
		t.Errorf("Too small input did not return a nil key residue")
	}

	if err == nil {
		t.Errorf("No error was returned with too small input")
	} else if !strings.Contains(err.Error(), keyResidueIncorrectLenErr) {
		t.Errorf("wrong error returned when too small input: %s", err)
	}
}

// Consistency test of KeyResidue.String.
func TestKeyResidue_String(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"sMweiL8i...",
		"Vm9LKiZh...",
		"ygQoB7ig...",
		"KcIeQV/j...",
	}

	for _, exp := range expected {

		randData := make([]byte, 32)
		prng.Read(randData)
		k := Key{}
		copy(k[:], randData)
		kr := NewKeyResidue(k)

		if kr.String() != exp {
			t.Errorf("Key Residue string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				kr.String())
		}
	}
}

// Consistency test of KeyResidue.StringVerbose.
func TestKeyResidue_StringVerbose(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"sMweiL8iqwQ6sSvKpeNI6X75Q62PNjjtRuXwdsgdsYs=",
		"Vm9LKiZhyLTjU9CAZun0vcC3ppYrSKyv8Ve3PRPTs14=",
		"ygQoB7igwNbvAHNepSmbW36YDm3vxfE6CbmB5F4/wBQ=",
		"KcIeQV/jKvxfvVmrrlzAFPhWZR9chJv1smu+nDAdppg=",
	}

	for _, exp := range expected {

		randData := make([]byte, 32)
		prng.Read(randData)
		k := Key{}
		copy(k[:], randData)
		kr := NewKeyResidue(k)

		if kr.StringVerbose() != exp {
			t.Errorf("Key Residue string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				kr.StringVerbose())
		}
	}
}

// Consistency test of KeyResidue.Marshal.
func TestKeResidue_Marshal(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"sMweiL8iqwQ6sSvKpeNI6X75Q62PNjjtRuXwdsgdsYs=",
		"Vm9LKiZhyLTjU9CAZun0vcC3ppYrSKyv8Ve3PRPTs14=",
		"ygQoB7igwNbvAHNepSmbW36YDm3vxfE6CbmB5F4/wBQ=",
		"KcIeQV/jKvxfvVmrrlzAFPhWZR9chJv1smu+nDAdppg=",
	}

	for _, exp := range expected {

		randData := make([]byte, 32)
		prng.Read(randData)
		k := Key{}
		copy(k[:], randData)

		mid := NewKeyResidue(k)

		if base64.StdEncoding.EncodeToString(mid.Marshal()) != exp {
			t.Errorf("Key Residue string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				base64.StdEncoding.EncodeToString(mid.Marshal()))
		}
	}
}

// Tests that a KeyResidue marshalled by KeyResidue.Marshal and unmarshalled
// with UnmarshalKeyResidue
// produces the correct full result. This is a consistency test.
func TestKeyResidue_Marshal_UnmarshalKeyResidue(t *testing.T) {
	prng := rand.New(rand.NewSource(68700))

	expected := newTestKeyResidue(prng)

	data, err := json.Marshal(expected)
	if err != nil {
		t.Errorf("Failed to JSON marshal %T: %+v", expected, err)
	}

	var residue KeyResidue
	err = json.Unmarshal(data, &residue)
	if err != nil {
		t.Errorf("Failed to JSON umarshal %T: %+v", residue, err)
	}

	if expected != residue {
		t.Errorf("Marshalled and unamrshalled KeyResidue does not match "+
			"expected.\nexpected: %s\nreceived: %s", expected, residue)
	}
}

func newTestKeyResidue(prng *rand.Rand) KeyResidue {
	baseKeyBytes := make([]byte, grp.GetP().ByteLen())
	prng.Read(baseKeyBytes)
	baseKeyBytes[0] &= 0x7f
	baseKey := grp.NewIntFromBytes(baseKeyBytes)

	keyNum := prng.Uint32()

	key := DeriveKey(baseKey, keyNum)
	return NewKeyResidue(key)
}
