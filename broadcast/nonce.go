package broadcast

import (
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
)

// newNonce generates a nonce used for key generation for encryption and
// decryption of the broadcast payloads. key = H(symmetric key, nonce).
// The nonce is 256 bits in length and generated randomly. The nonce ensures
// there will not be collisions under the birthday paradox of 256 bits.
// Because the symmetric broadcast payload does not use the fingerprint
// structure, which is also 256 bits in length, the nonce is stored in the
// unused fingerprints field.
// The fingerprints structure actually only gives 255 bits because the leading
// bit is used in the cyclic group, a requirement for the cMix protocol. The
// birthday paradox is satisfied with 255 bits.
func newNonce(csprng csprng.Source) format.Fingerprint {
	fp := format.NewFingerprint(cmix.NewSalt(csprng, format.KeyFPLen))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0x7F

	return fp
}
