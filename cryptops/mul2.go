////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type Mul2Prototype func(g *cyclic.Group, ecr, key *cyclic.Int) *cyclic.Int

// Mul2 multiplies 2 numbers in a cyclic group within the cryptops interface.
// Sets `out = x*out mod p` and returns out.
var Mul2 Mul2Prototype = func(g *cyclic.Group, x, out *cyclic.Int) *cyclic.Int {
	g.Mul(out, x, out)
	return out
}

// GetName returns the name for debugging
func (Mul2Prototype) GetName() string {
	return "Mul2"
}

// GetInputSize returns the input size, used in safety checks
func (Mul2Prototype) GetInputSize() uint32 {
	return 1
}
