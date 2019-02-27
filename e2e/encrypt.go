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
