////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"crypto/hmac"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
)

const macMask = 0b00111111

// IsUnencrypted determines if the message is unencrypted by comparing the hash
// of the message payload to the MAC. Returns true if the message is unencrypted
// and false otherwise.
// the highest bit of the recipient ID is stored in the highest bit of the MAC
// field. This is accounted for and the id is reassembled, with a presumed user
// type
func IsUnencrypted(m format.Message) (bool, *id.ID) {

	expectedMac := makeUnencryptedMAC(m.GetContents())
	receivedMac := m.GetMac()
	idHighBit := (receivedMac[0] & 0b01000000) << 1
	receivedMac[0] &= macMask

	//return false if the message is not unencrypted
	if !hmac.Equal(expectedMac, receivedMac) {
		return false, nil
	}

	//extract the user ID
	idBytes := m.GetKeyFP()
	idBytes[0] |= idHighBit
	uid := id.ID{}
	copy(uid[:], idBytes[:])
	uid.SetType(id.User)

	// Return true if the byte slices are equal
	return true, &uid
}

// SetUnencrypted sets up the condition where the message would be determined to
// be unencrypted by setting the MAC to the hash of the message payload.
func SetUnencrypted(payload []byte, uid *id.ID) ([]byte, format.Fingerprint) {
	mac := makeUnencryptedMAC(payload)

	//copy in the high bit of the userID for storage
	mac[0] |= (uid[0] & 0b10000000) >> 1

	//remove the type byte off of the userID and clear the highest bit so
	//it can be stored in the fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], uid[:format.KeyFPLen])
	fp[0] &= 0b01111111

	return mac, fp
}

func makeUnencryptedMAC(payload []byte) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()

	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Hash the message payload
	h.Write(payload)
	payloadHash := h.Sum(nil)

	//set the first bit as zero to ensure everything stays in the group
	payloadHash[0] &= macMask

	return payloadHash
}
