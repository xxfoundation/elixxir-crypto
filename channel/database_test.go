////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"bytes"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

// TestCrypt_DiscardPadding_AllZeroes tests discardPadding.
// Test Case: Data passed is all zeroes, meaning it should
// all be considered padding.
func TestCrypt_DiscardPadding_AllZeroes(t *testing.T) {
	// Construct empty data (all 0's)
	data := make([]byte, 32)

	// Discard padding should return an empty byte slice
	parsed := discardPadding(data)
	if len(parsed) != 0 {
		t.Errorf("Discard padding shoould have removed all "+
			"data from %v", data)
	}

}

// TestCrypt_DiscardPadding_NotAllZeroes tests discardPadding.
// Test Case: Data passed is not all zeroes, meaning only all trailing zeroes
// should be discarded.
func TestCrypt_DiscardPadding_NotAllZeroes(t *testing.T) {
	// Populate the first byte with non padding data
	data := make([]byte, 32)
	data[0] = 11

	// Discard padding should return the first byte of data
	parsed := discardPadding(data)
	expected := []byte{11}
	if !bytes.Equal(parsed, expected) {
		t.Fatalf("discardPadding did not produce expected output."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, parsed)
	}
}

// TestCrypt_AppendPadding_NilCase tests appendPadding.
// Test Case: Ensure that given nil and a non-zero entry length, an empty
// byte slice of entry length is produced.
func TestCrypt_AppendPadding_NilCase(t *testing.T) {
	entryLength := 32
	expected := make([]byte, entryLength)

	received := appendPadding(nil, entryLength)
	if !bytes.Equal(received, expected) {
		t.Fatalf("appendPadding did not produce expected output."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}

}

// TestCrypt_AppendPadding_SmallData tests appendPadding.
// Test Case: Ensure that given a non-zero entry length and some data less
// than entry length, appendPadding pads the data with zero data up to entry
// length.
func TestCrypt_AppendPadding_SmallData(t *testing.T) {
	entryLength := 32
	expected := make([]byte, entryLength)

	smallData := []byte("123")
	copy(expected, smallData)
	received := appendPadding(smallData, entryLength)
	if !bytes.Equal(received, expected) {
		t.Fatalf("appendPadding did not produce expected output."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}

}

// TestCrypt_AppendPadding_LargeData tests appendPadding.
// Test Case: Ensure that given a non-zero entry length and some data larger
// than entry length, appendPadding does not modify the data.
func TestCrypt_AppendPadding_LargeData(t *testing.T) {
	entryLength := 32

	largeData := make([]byte, entryLength*2)

	received := appendPadding(largeData, entryLength)
	if !bytes.Equal(received, largeData) {
		t.Fatalf("appendPadding should not modify data which is larger than the "+
			"standard entry length (%d)."+
			"\nExpected: %v"+
			"\nReceived: %v", entryLength, largeData, received)
	}

}

// TestCrypt_AppendPadding_ZeroEntryLength tests appendPadding.
// Test Case: Ensure that given a zero value entry length, no padding occurs.
func TestCrypt_AppendPadding_ZeroEntryLength(t *testing.T) {
	entryLength := 0

	expected := []byte("some random data")

	received := appendPadding(expected, entryLength)

	if !bytes.Equal(expected, received) {
		t.Fatalf("appendPadding should not modify data when the standard entry "+
			"length is 0."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}

}

// TestCrypt_AppendPadding_ZeroEntryLength tests both appendPadding and
// discardPadding.
// Test Case: Ensure discardPadding will return the original data passed into
// appendPadding.
func TestCrypt_AppendPadding_DiscardPadding(t *testing.T) {
	entryLength := 250
	expected := []byte("expected data")

	appendedData := appendPadding(expected, entryLength)
	received := discardPadding(appendedData)

	if !bytes.Equal(expected, received) {
		t.Fatalf("discardPadding did not produce expected value."+
			"\nExpected: %v"+
			"\nRecieved: %v", expected, received)
	}
}

// TestCrypt_EncryptDecrypt tests Cipher.Encrypt and Cipher.Decrypt.
// Test Case: Ensure that Cipher.Decrypt returns the originally encrypted
// plaintext when passed the output from Cipher.Encrypt.
func TestCrypt_EncryptDecrypt(t *testing.T) {
	password := []byte("test123")
	rng := csprng.NewSystemRNG()
	salt := []byte("salt")
	entryLength := 50
	expected := []byte("original")
	c := NewCipher(password, salt, entryLength, rng)

	encryptedData := c.Encrypt(expected)
	decryptedData, err := c.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("Decrypt returned an error: %+v", err)
	}

	if !bytes.Equal(expected, decryptedData) {
		t.Fatalf("Cipher.Decrypt did not return originally encrypted data."+
			"\nExpected: %v"+
			"\nRecieved: %v", expected, decryptedData)
	}

}
