////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// SaltLen is the length, in bytes, of the salt used to generate the key
// fingerprint.
const SaltLen = 32

// NewKeyFingerprint generates a key fingerprint for the member of a group from
// the group key, 256-bit salt, and the member's recipient ID.
func NewKeyFingerprint(groupKey Key, salt [32]byte, recipientID *id.ID) format.Fingerprint {

	// Hash the group key, recipient ID, and salt
	h, _ := blake2b.New256(nil)
	h.Write(groupKey[:])
	h.Write(recipientID.Bytes())
	h.Write(salt[:])

	// Create new key fingerprint from hash
	keyFingerprint := format.NewFingerprint(h.Sum(nil))

	// Set the first bit to be 0 to comply with the group requirements in the
	// cMix message format.
	keyFingerprint[0] &= 0x7F

	return keyFingerprint
}

// CheckKeyFingerprint verifies that the given fingerprint matches the provided
// group data.
func CheckKeyFingerprint(fingerprint format.Fingerprint, groupKey Key,
	salt [SaltLen]byte, recipientID *id.ID) bool {

	return fingerprint == NewKeyFingerprint(groupKey, salt, recipientID)
}
