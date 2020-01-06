////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"bytes"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

// IsUnencrypted determines if the message is unencrypted by comparing the hash
// of the message payload to the MAC. Returns true if the message is unencrypted
// and false otherwise.
func IsUnencrypted(m *format.Message) bool {
	// Create new hash
	h, err := hash.NewCMixHash()

	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Hash the message payload
	h.Write(m.Contents.Get())
	payloadHash := h.Sum(nil)

	// Return true if the byte slices are equal
	return bytes.Equal(payloadHash, m.AssociatedData.GetMAC())
}

// SetUnencrypted sets up the condition where the message would be determined to
// be unencrypted by setting the MAC to the hash of the message payload.
func SetUnencrypted(m *format.Message) {
	// Create new hash
	h, err := hash.NewCMixHash()

	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Hash the message payload
	h.Write(m.Contents.Get())
	payloadHash := h.Sum(nil)

	// Set the MAC
	m.AssociatedData.SetMAC(payloadHash)
}
