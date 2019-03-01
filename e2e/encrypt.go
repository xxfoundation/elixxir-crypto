package e2e

import (
	"crypto/rand"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"io"
)

// Calls encrypt() with crypto.rand.Reader.
func Encrypt(g cyclic.Group, key *cyclic.Int, msg []byte) ([]byte, error) {
	return encrypt(g, key, msg, rand.Reader)
}

// Modular multiplies the key and padded message under the passed group.
func encrypt(g cyclic.Group, key *cyclic.Int, msg []byte,
	rand io.Reader) ([]byte, error) {
	// Get the padded message
	encMsg, err := pad(msg, int(format.TOTAL_LEN), rand)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Modular multiply the key with the padded message
	product := g.Mul(key, cyclic.NewIntFromBytes(encMsg), cyclic.NewInt(0))

	// Return the result
	return product.Bytes(), nil
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
func Decrypt(g cyclic.Group, key *cyclic.Int, encMsg []byte) ([]byte, error) {
	// Modular invert the key under the group
	keyInv := g.Inverse(key, cyclic.NewInt(0))

	// Modular multiply the inverted key with the message
	product := g.Mul(keyInv, cyclic.NewIntFromBytes(encMsg), cyclic.NewInt(0))

	// Remove the padding from the message
	unPadMsg, err := Unpad(product.LeftpadBytes(uint64(format.TOTAL_LEN)))

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Convert the byte slice into a cyclic int and return
	return unPadMsg, nil
}
