////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type RootCoprimePrototype func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int

// Implements cyclic.Group RootCoprime() within the cryptops interface.
// Sets z = y√x mod p, and returns z.
// Only works with y's coprime with g.prime-1 (g.psub1)
var RootCoprime RootCoprimePrototype = func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int {
	return g.RootCoprime(x,y,z)
}

// Returns the function name for debugging.
func (RootCoprimePrototype) GetName() string {
	return "RootCoprime"
}

// Returns the input size; used in safety checks.
func (RootCoprimePrototype) GetInputSize() uint32 {
	return 1
}
