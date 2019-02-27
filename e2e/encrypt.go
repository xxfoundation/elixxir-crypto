package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
)

// Modular multiplies the specified key and padded message under the passed
// group.
func Encrypt(g cyclic.Group, key, msg cyclic.Int) (cyclic.Int, error) {
	// Get the padded message
	encMsg, err := Pad(msg.Bytes(), msg.BitLen())

	// Return if an error occurred
	if err != nil {
		return *cyclic.NewIntFromBytes(encMsg), err
	}

	product := cyclic.NewInt(0)

	// Modular multiply the key with the padded message
	product = g.Mul(&key, cyclic.NewIntFromBytes(encMsg), product)

	// Return the result
	return *product, nil
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
func Decrypt(g cyclic.Group, key, encMsg cyclic.Int) cyclic.Int {
	keyInv := cyclic.NewInt(0)

	// Modular invert the key under the group
	keyInv = g.Inverse(&key, keyInv)

	product := cyclic.NewInt(0)

	// Modular multiply the inverted key with the message
	product = g.Mul(keyInv, &encMsg, product)

	// Return the result
	return *product
}
