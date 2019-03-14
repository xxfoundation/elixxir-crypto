package e2e

import (
	"bytes"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

// Determines if the message is unencrypted by comparing the hash of the message
// payload to the key fingerprint. Returns true if the message is unencrypted
// and false otherwise.
func IsUnencrypted(m *format.Message) bool {
	// Create new hash
	h, err := hash.NewCMixHash()

	if err != nil {
		jww.ERROR.Printf("Failed to create hash: %v", err)
	}

	// Hash the message payload
	h.Write(m.SerializePayload())
	payloadHash := h.Sum(nil)

	// Get the key fingerprint
	keyFingerprint := m.GetKeyFingerprint()

	// Return true if the byte slices are equal
	return bytes.Equal(payloadHash, keyFingerprint[:])
}
