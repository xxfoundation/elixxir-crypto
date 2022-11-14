package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
)

// PSSOptions is a direct wrapper for rsa.PSSOptions
type PSSOptions struct {
	gorsa.PSSOptions
}

// NewDefaultPSSOptions returns signing options that set the salt length equal
// to the length of the hash and uses the default cMix Hash algorithm.
func NewDefaultPSSOptions() *PSSOptions {
	return &PSSOptions{
		gorsa.PSSOptions{
			SaltLength: gorsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.BLAKE2b_256,
		},
	}
}
