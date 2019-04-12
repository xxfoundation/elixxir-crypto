package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type Mul2Prototype func(g *cyclic.Group, ecr, key *cyclic.Int) *cyclic.Int

// Multiplies 2 numbers in a cyclic group within the cryptops interface.
// Sets `out = x*out mod p` and returns out.
var Mul2 Mul2Prototype = func(g *cyclic.Group, x, out *cyclic.Int) *cyclic.Int {
	g.Mul(out, x, out)
	return out
}

// Returns the name for debugging
func (Mul2Prototype) GetName() string {
	return "Mul2"
}

// Returns the input size, used in safety checks
func (Mul2Prototype) GetInputSize() uint32 {
	return 1
}