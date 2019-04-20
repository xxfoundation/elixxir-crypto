package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

// Modular multiplies the key and message under the passed group.
// DOES NOT PAD message, so this could be unsafe if message is too small
func EncryptUnsafe(g *cyclic.Group, key *cyclic.Int, msg []byte) []byte {
	// Modular multiply the key with the message
	product := g.Mul(key, g.NewIntFromBytes(msg), g.NewInt(1))
	// Return the result
	return product.LeftpadBytes(uint64(format.TOTAL_LEN))
}

// Encrypt a message by first padding it, using rand.Reader
// Modular multiplies the key and padded message under the passed group.
func Encrypt(g *cyclic.Group, key *cyclic.Int, msg []byte) ([]byte, error) {
	// Get the padded message
	encMsg, err := Pad(msg, int(format.TOTAL_LEN))

	// Return if an error occurred
	if err != nil {
		return nil, err
	}
	return EncryptUnsafe(g, key, encMsg), nil
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
func DecryptUnsafe(g *cyclic.Group, key *cyclic.Int, encMsg []byte) []byte {
	// Modular invert the key under the group
	keyInv := g.Inverse(key, g.NewInt(1))
	// Modular multiply the inverted key with the message
	product := g.Mul(keyInv, g.NewIntFromBytes(encMsg), g.NewInt(1))
	return product.LeftpadBytes(uint64(format.TOTAL_LEN))
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
// Then removes padding from the message
func Decrypt(g *cyclic.Group, key *cyclic.Int, encMsg []byte) ([]byte, error) {
	decMsg := DecryptUnsafe(g, key, encMsg)

	// Remove the padding from the message
	unPadMsg, err := Unpad(decMsg)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}
	return unPadMsg, nil
}
