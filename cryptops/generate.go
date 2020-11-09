////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

import (
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
)

// GeneratePrototype is the function type for generating phase and sharing keys.
// phase keys are those used to encrypt/decrypt/permute during realtime, and
// share keys are used to share the phase keys under encryption.
type GeneratePrototype func(g *cyclic.Group, phaseKey,
	exponentKey *cyclic.Int, exponentKeySize int, rng csprng.Source) error

// Generate implements the Generate Prototype.
//
// Previously the share key was 256 bits, generated per guidelines here:
//   https://www.keylength.com/en/4/
//
// Has been changes to 2048 due to security concerns
var Generate GeneratePrototype = func(g *cyclic.Group, phaseKey,
	exponentKey *cyclic.Int, exponentKeySize int, rng csprng.Source) error {
	p := g.GetPBytes()
	var exponentKeyBytes, phaseKeyBytes []byte
	var err error

	exponentKeyBytes, err = csprng.GenerateInGroup(p, exponentKeySize, rng)
	if err != nil {
		return err
	}
	phaseKeyBytes, err = csprng.GenerateInGroup(p, len(p), rng)
	if err != nil {
		return err
	}

	g.SetBytes(exponentKey, exponentKeyBytes)
	g.SetBytes(phaseKey, phaseKeyBytes)
	return nil
}

// GetName returns the name of the Generate cryptop, "Generate"
func (GeneratePrototype) GetName() string {
	return "Generate"
}

// GetInputSize returns the input size (the number of parallel computations
// it does at once)
func (GeneratePrototype) GetInputSize() uint32 {
	return uint32(1)
}
