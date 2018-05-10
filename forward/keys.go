package forward

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
)

// ExpandKey is a function that receives a key and a salt and expands such key to a specific size
// This implementation returns a 2048 bit-size key (or 256 bytes)
func ExpandKey(key []byte, salt []byte) ([]byte, error) {

	if len(key) < 32 || len(salt) < 32 {
		return nil, errors.New("ExpandKey(): invalid size either in the base key or the salt")
	} else {
		return pbkdf2.Key(key, salt, 1, 256, sha512.New), nil
	}
}

// UpdateKey is a function that updates the current Key to be used to encrypt/decrypt
// This function receives a base key generated during the registration and adds entropy by using
// two different hash functions
func UpdateKey(baseKey, salt []byte) ([]byte, error) {

	if len(baseKey) < 32 || len(salt) < 32 {

		return nil, errors.New("UpdateKey(): invalid size either in the base key or the salt")

	} else {
		// Append the base key and the received salt to generate a random input
		a := append(baseKey, salt...)

		//Blake2b Hash of the result of previous stage (base key + salt)
		b := blake2b.Sum256(a)
		x := b[:]

		//Different Hash (SHA256) of the previous result to add entropy
		h := sha256.New()
		h.Write(x)
		y := h.Sum(nil)

		// Expand Key
		z, err := ExpandKey(y, salt)

		return z, err
	}
}
