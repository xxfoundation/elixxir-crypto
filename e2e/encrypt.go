package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

// Modular multiplies the specified key and padded message under the passed
// group.
func Encrypt(g cyclic.Group, key, msg *cyclic.Int) (*cyclic.Int, error) {
	// Get the padded message
	encMsg, err := Pad(msg.Bytes(), format.TOTAL_LEN)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Modular multiply the key with the padded message
	product := g.Mul(key, cyclic.NewIntFromBytes(encMsg), cyclic.NewInt(0))

	// Return the result
	return product, nil
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
func Decrypt(g cyclic.Group, key, encMsg *cyclic.Int) (*cyclic.Int, error) {
	// Modular invert the key under the group
	keyInv := g.Inverse(key, cyclic.NewInt(0))

	// Modular multiply the inverted key with the message
	product := g.Mul(keyInv, encMsg, cyclic.NewInt(0))

	// Remove the padding from the message
	unPadMsg, err := Unpad(produc.LeftpadBytes(format.TOTAL_LEN))

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Convert the byte slice into a cyclic int and return
	return cyclic.NewIntFromBytes(unPadMsg), nil
}
