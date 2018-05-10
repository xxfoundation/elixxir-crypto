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

//NewBlakeHash receives the payload to be hashed and outputs a 256 bit Blake2b hash in the []byte format
func NewBlakeHash(payload []byte) []byte {

	x := blake2b.Sum256(payload)

	return x[:]
}

//NewSHA256 returns a fixed-size (256 bit) SHA256 hash in a byte format
// Function receives the payload to be hashed and outputs a 256 bit hash in the []byte format
func NewSHA256(payload []byte) []byte {

	h := sha256.New()
	h.Write(payload)

	return h.Sum(nil)
}

// NewHMAC creates a new Message Authentication Code from a message payload and a key.
// This function does not accept keys that are less than 256 bits (or 32 bytes)
func NewHMAC(message, key []byte) ([]byte, error) {

	if len(key) < 32 {

		return nil, errors.New("NewHMAC(): key size is too small")

	} else {

		h := hmac.New(sha256.New, key)
		h.Write(message)

		return h.Sum(nil), nil
	}
}

// CheckHMAC receives a MAC value along with the respective message and key associated with the Message Authentication Code.
// Returns true if calculated MAC matches the received one. False if not.
func CheckHMAC(message, MAC, key []byte) bool {

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
