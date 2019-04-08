package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

// Sets z = z**y mod p and returns z.
func Exp(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int {
	return g.Exp(x, y, z)
}
