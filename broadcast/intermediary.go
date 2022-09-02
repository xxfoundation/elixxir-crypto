package broadcast

import (
	"golang.org/x/crypto/blake2b"
)

func deriveIntermediary(name, description string, salt, rsaPub, secret []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write([]byte(name))
	if err != nil {
		panic(err)
	}
	_, err = h.Write([]byte(description))
	if err != nil {
		panic(err)
	}
	_, err = h.Write(rsaPub)
	if err != nil {
		panic(err)
	}
	// secret is hashed first so that
	// we can share all the inputs to the
	// hkdf without giving out the secret.
	secretHash := blake2b.Sum256(secret)
	_, err = h.Write(secretHash[:])
	if err != nil {
		panic(err)
	}
	_, err = h.Write(salt)
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}
