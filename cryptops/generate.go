////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import (
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
)

// GeneratePrototype is the function type for generating phase and sharing keys.
// phase keys are those used to encrypt/decrypt/permute during realtime, and
// share keys are used to share the phase keys under encryption.
type GeneratePrototype func(g *cyclic.Group, phaseKey,
	shareKey *cyclic.Int, rng csprng.Source) error

// Generate implements the Generate Prototype. Notably the share key is
// 256 bits, generated per guidelines here:
//   https://www.keylength.com/en/4/
var Generate GeneratePrototype = func(g *cyclic.Group, phaseKey,
	shareKey *cyclic.Int, rng csprng.Source) error {
	p := g.GetPBytes()
	var shareKeyBytes, phaseKeyBytes []byte
	var err error

	shareKeyBytes, err = csprng.GenerateInGroup(p, 32, rng)
	if err != nil {
		return err
	}
	phaseKeyBytes, err = csprng.GenerateInGroup(p, len(p), rng)
	if err != nil {
		return err
	}

	g.SetBytes(shareKey, shareKeyBytes)
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
