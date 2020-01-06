////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type ExpPrototype func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int

// Exp implements cyclic.Group Exp() within the cryptops interface.
// Sets z = z**y mod p and returns z.
var Exp ExpPrototype = func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int {
	return g.Exp(x, y, z)
}

// GetName returns the function name for debugging.
func (ExpPrototype) GetName() string {
	return "Exp"
}

// GetInputSize returns the input size; used in safety checks.
func (ExpPrototype) GetInputSize() uint32 {
	return 1
}
