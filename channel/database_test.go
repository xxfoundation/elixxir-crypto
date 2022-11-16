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

// TestCrypt_DiscardPadding tests discardPadding.
// Test Case: Basic unit test, ensuring that lengthOfPlaintext bytes are pulled
// from the passed in byte data.
func TestCrypt_DiscardPadding(t *testing.T) {
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

// TestCrypt_AppendPadding_SmallData tests appendPadding.
// Test Case: Ensure that given a non-zero entry length and some data less
// than entry length, appendPadding pads the data with zero data up to entry
// length.
func TestCrypt_AppendPadding_SmallData(t *testing.T) {
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

// TestCrypt_AppendPadding_ZeroEntryLength tests both appendPadding and
// discardPadding.
// Test Case: Ensure discardPadding will return the original data passed into
// appendPadding.
func TestCrypt_AppendPadding_DiscardPadding(t *testing.T) {
	blockSize := 250
	expected := []byte("expected data")

	rng := csprng.NewSystemRNG()

	appendedData, err := appendPadding(expected, blockSize, rng)
	if err != nil {
		t.Fatalf("appendPadding error: %+v", err)
	}
	received := discardPadding(appendedData)

	if !bytes.Equal(expected, received) {
		t.Fatalf("discardPadding did not produce expected value."+
			"\nExpected: %v"+
			"\nRecieved: %v", expected, received)
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
