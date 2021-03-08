////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

import (
	"gitlab.com/elixxir/crypto/cyclic"
)

type RootCoprimePrototype func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int

// RootCoprime implements cyclic.Group RootCoprime() within the cryptops interface.
// Sets tmp = y√x mod p, and returns z.
// Only works with y's coprime with g.prime-1 (g.psub1)
var RootCoprime RootCoprimePrototype = func(g *cyclic.Group, x, y, z *cyclic.Int) *cyclic.Int {
	return g.RootCoprime(x, y, z)
}

// GetName returns the function name for debugging.
func (RootCoprimePrototype) GetName() string {
	return "RootCoprime"
}

// GetInputSize returns the input size; used in safety checks.
func (RootCoprimePrototype) GetInputSize() uint32 {
	return 1
}
