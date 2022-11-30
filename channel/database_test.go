////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"bytes"
	"encoding/binary"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

// TestCrypt_EncryptDecrypt tests Cipher.Encrypt and Cipher.Decrypt.
// Test Case: Ensure that Cipher.Decrypt returns the originally encrypted
// plaintext when passed the output from Cipher.Encrypt.
func TestCrypt_EncryptDecrypt(t *testing.T) {
	// Construct cipher
	password := []byte("test123")
	rng := csprng.NewSystemRNG()
	salt := []byte("salt")
	blockSize := 50
	expected := []byte("original")
	c, err := NewCipher(password, salt, blockSize, rng)
	if err != nil {
		t.Fatalf("Failed to create cipher: %+v", err)
	}

	encryptedData, err := c.Encrypt(expected)
	if err != nil {
		t.Fatalf("Encrypt error: %+v", err)
	}
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

// TestCrypt_EncryptDecrypt tests Cipher.Encrypt.
// Test Case: Ensure that Cipher.Encrypt returns an error if the plaintext
// is larger than the pre-defined block size.
func TestCipher_Encrypt_PlaintextTooLarge(t *testing.T) {
	blockSize := 256

	// Construct a plaintext larger than blockSize
	plaintext := make([]byte, blockSize*2)

	// Construct cipher
	password := []byte("test123")
	rng := csprng.NewSystemRNG()
	salt := []byte("salt")
	c, err := NewCipher(password, salt, blockSize, rng)
	if err != nil {
		t.Fatalf("Failed to create cipher: %+v", err)
	}

	_, err = c.Encrypt(plaintext)
	if err == nil {
		t.Fatalf("Encrypt should fail when plaintext is too large.")
	}
}

// Tests that a number of plaintexts with different block sizes can have padding
// added via appendPadding and discarded via discardPadding and match the
// original.
func Test_appendPadding_discardPadding(t *testing.T) {
	rng := csprng.NewSystemRNG()
	tests := []struct {
		plaintext []byte
		blockSize int
	}{
		{[]byte("TestMessage"), 256},
		{[]byte("Lorem Ipsum"), 16},
		{bytes.Repeat([]byte("A"), 256), 256},
		{bytes.Repeat([]byte("A"), 255), 256},
		{[]byte{}, 256},
		{[]byte{5}, 1},
		{[]byte{}, 0},
	}

	for i, tt := range tests {
		paddedData, err := appendPadding(tt.plaintext, tt.blockSize, rng)
		if err != nil {
			t.Fatalf("Failed to padd plaintext %d: %+v", i, err)
		}

		plaintext := discardPadding(paddedData)

		if !bytes.Equal(tt.plaintext, plaintext) {
			t.Fatalf("Encoded and decoded plaintext does not match expected."+
				"\nexpected: %q\nrecieved: %v", tt.plaintext, plaintext)
		}
	}
}

// Ensure that given a non-zero entry length and some data less than entry
// length, appendPadding pads the data with zero data up to entry length.
func Test_appendPadding_SmallData(t *testing.T) {
	blockSize := 32
	smallData := []byte("123")

	// Use insecure seeded rng for reproducibility
	notRand := &CountingReader{count: uint8(0)}

	// Serialize length of plaintext
	plaintextSizeBytes := make([]byte, lengthOfOverhead)
	plaintextSize := len(smallData)
	binary.PutUvarint(plaintextSizeBytes, uint64(plaintextSize))

	// Construct padding
	padding := make([]byte, blockSize-plaintextSize)
	_, _ = notRand.Read(padding)
	expected := append(plaintextSizeBytes, smallData...)
	expected = append(expected, padding...)

	received, err := appendPadding(
		smallData, blockSize, &CountingReader{count: uint8(0)})
	if err != nil {
		t.Fatalf("appendPadding returned an unexpected error: %+v", err)
	}
	if !bytes.Equal(received, expected) {
		t.Fatalf("appendPadding did not produce expected output."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}
}

// Tests that lengthOfPlaintext bytes are pulled from the passed in byte data.
func Test_discardPadding(t *testing.T) {
	expected := []byte("123")
	plaintextSizeBytes := make([]byte, lengthOfOverhead)
	binary.PutUvarint(plaintextSizeBytes, uint64(len(expected)))

	padding := make([]byte, 245)
	data := append(plaintextSizeBytes, expected...)
	data = append(data, padding...)

	received := discardPadding(data)

	if !bytes.Equal(expected, received) {
		t.Fatalf("DiscardPadding did not output expected result."+
			"\nExpected: %+v"+
			"\nReceived: %+v", expected, received)
	}
}

type CountingReader struct {
	count uint8
}

// Read just counts until 254 then starts over again
func (c *CountingReader) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		c.count = (c.count + 1) % 255
		b[i] = c.count
	}
	return len(b), nil
}
