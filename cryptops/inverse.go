////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

// An alias for a unary inverse operation which sets and returns an out variable
type InversePrototype func(g *cyclic.Group, x, out *cyclic.Int) *cyclic.Int

// Inverse inverts a number x in the group and stores it in out.
// It also returns out.
var Inverse InversePrototype = func(g *cyclic.Group, x, out *cyclic.Int) *cyclic.Int {
	g.Inverse(x, out)
	return out
}

// GetName returns the function name for debugging.
func (InversePrototype) GetName() string {
	return "Inverse"
}

// GetInputSize returns the input size; used in safety checks.
func (InversePrototype) GetInputSize() uint32 {
	return 1
}
