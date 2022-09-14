package broadcast

import (
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
)

// secret is hashed first so that
// we can share all the inputs to the
// hkdf without giving out the secret.
func hashSecret(secret []byte) []byte {
	b := blake2b.Sum256(secret)
	return b[:]
}

// returns the Blake2b hash of the given arguments:
// H(name | description | rsaPubHash | hashedSecret | salt)
func deriveIntermediary(name, description string, salt, rsaPubHash, hashedSecret []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	_, err = h.Write([]byte(name))
	if err != nil {
		jww.FATAL.Panic(err)
	}
	_, err = h.Write([]byte(description))
	if err != nil {
		jww.FATAL.Panic(err)
	}
	_, err = h.Write(rsaPubHash)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	_, err = h.Write(hashedSecret)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	_, err = h.Write(salt)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return h.Sum(nil)
}
