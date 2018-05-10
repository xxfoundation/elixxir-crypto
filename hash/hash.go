package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/blake2b"
	"hash"
)

// NewCMixHash returns the current cMix hash implementation
// which is currently the 256 bit version of blake2b
func NewCMixHash() (hash.Hash, error) {

	return blake2b.New256(nil)
}

// NewHMAC creates a new Message Authentication Code from a message payload and a key.
// This function does not accept keys that are less than 256 bits (or 32 bytes)
func CreateHMAC(message, key []byte) ([]byte, error) {

	if len(key) < 32 {

		return nil, errors.New("CreateHMAC(): key size is too small")

	} else {
		h := hmac.New(sha256.New, key)
		h.Write(message)

		return h.Sum(nil), nil
	}
}

// CheckHMAC receives a MAC value along with the respective message and key associated with the Message Authentication Code.
// Returns true if calculated MAC matches the received one. False if not.
func VerifyHMAC(message, MAC, key []byte) bool {

	if len(key) < 32 {
		//TODO: SEND THIS TO LOGGING?
		return false
	} else {

		mac := hmac.New(sha256.New, key)
		mac.Write(message)
		expectedMAC := mac.Sum(nil)

		return hmac.Equal(MAC, expectedMAC)
	}
}
