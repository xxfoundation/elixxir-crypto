////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	"bytes"
	"crypto/sha256"
)

// Interface for signing generically
type GenericSignable interface {
	Marshal() []byte // Match usage in signing
	GetSignature() []byte
	SetSignature([]byte)
	ClearSignature()
}

// Sign takes a genericSignable object, marshals the data intended to be signed.
// It hashes that data and sets it as the signature of that object
func Sign(signable GenericSignable) {
	// Clear any value in the signature field
	signable.ClearSignature()

	// Get the data that is to be signed
	data := signable.Marshal()

	// Hash the data
	h := sha256.New()
	h.Write([]byte(data))

	// And set that hashed data as the signature
	signable.SetSignature(h.Sum(nil))
}

// Verify takes the signature from the object and clears it out.
// It then re-creates the signature and compares it to the original signature.
// If the recreation matches the original signature it returns true,
// else it returns false
func Verify(verifiable GenericSignable) bool {
	// Take the signature from the object
	sig := verifiable.GetSignature()

	// Clear the signature
	verifiable.ClearSignature()

	// Get the data to replicate the signature
	data := verifiable.Marshal()

	// Hash that data
	h := sha256.New()
	h.Write([]byte(data))
	ourHash := h.Sum(nil)

	// And compare it to the signature
	if bytes.Compare(sig, ourHash) == 0 {
		// If they are the same, then signature is valid
		return true
	}
	// Otherwise it has not been verified
	return false

}
