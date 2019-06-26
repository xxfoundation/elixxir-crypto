package e2e

import (
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

// Tests if IsUnencrypted() correctly determines an encrypted message as
// encrypted.
func TestIsUnencrypted_EncryptedMessage(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, 256)
	rand.Read(randSlice)
	fpSlice := make([]byte, 32)
	rand.Read(fpSlice)

	// Create message
	m := format.NewMessage()
	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)

	// Set the key fingerprint
	m.SetKeyFP(*format.NewFingerprint(fpSlice))

	// Check the message
	unencrypted := IsUnencrypted(m)

	if unencrypted == true {
		t.Errorf("IsUnencrypted() determined the message is unencrypted when it is actually encrypted\n\treceived: %v\n\texpected: %v", unencrypted, false)
	}
}

// Tests if IsUnencrypted() correctly determines an unencrypted message as
// unencrypted.
func TestIsUnencrypted_UnencryptedMessage(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, 256)
	rand.Read(randSlice)

	// Create message
	m := format.NewMessage()

	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)

	// Create new hash
	h, _ := hash.NewCMixHash()

	// Set the key fingerprint
	h.Write(m.Contents.Get())
	fp := *format.NewFingerprint(h.Sum(nil))
	m.SetKeyFP(fp)
	// Check the message
	unencrypted := IsUnencrypted(m)

	if unencrypted == false {
		t.Errorf("IsUnencrypted() determined the message is encrypted when it is actually unencrypted\n\treceived: %v\n\texpected: %v", unencrypted, true)
	}
}

// Tests if SetUnencrypted() makes a message unencrypted according to
// IsUnencrypted().
func TestSetUnencrypted(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, 256)
	rand.Read(randSlice)
	fpSlice := make([]byte, 32)
	rand.Read(fpSlice)
	// Create message
	m := format.NewMessage()

	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)
	// Set the key fingerprint
	m.SetKeyFP(*format.NewFingerprint(fpSlice))

	SetUnencrypted(m)

	if IsUnencrypted(m) == false {
		t.Errorf("SetUnencrypted() determined the message is encrypted when it should be unencrypted\n\treceived: %v\n\texpected: %v", IsUnencrypted(m), true)
	}
}
