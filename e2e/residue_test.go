////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/base64"
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

//tests that the wrong size error triggers correctly
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

// TestUnmarshalKeyResidue tests that UnmarshalKeyResidue
// produces the correct result.
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

//TestKeyResidue_String tests that ths KeyResidue.String function
// produces the correct truncated result. This is a consistency test.
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

//TestKeyResidue_StringVerbose tests that the KeyResidue.StringVerbose
// produces the correct full result. This is a consistency test.
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

// TestKeResidue_Marshal tests that KeyResidue.Marshal
// produces the correct full result. This is a consistency test.
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
