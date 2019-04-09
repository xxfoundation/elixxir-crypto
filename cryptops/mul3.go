package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

// It would be pretty easy to make this take a variable number of parameters
type Mul3Prototype func(g *cyclic.Group, x, y, z *cyclic.Int,
	out *cyclic.Int) *cyclic.Int

// Multiplies 3 numbers in a cyclic group within the cryptops interface.
// Sets `out = x*y*z mod p` and returns out.
var Mul3 Mul3Prototype = func(g *cyclic.Group, x, y, z,
	out *cyclic.Int) *cyclic.Int {
	return g.MulMulti(out, x, y, z)
}

// Returns the function name for debugging.
func (Mul3Prototype) GetName() string {
	return "Mul3"
}

// Returns the input size; used in safety checks.
func (Mul3Prototype) GetInputSize() uint32 {
	return 1
}
