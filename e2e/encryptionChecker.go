/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"bytes"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
)

const macMask = 0b00111111

// IsUnencrypted determines if the message is unencrypted by comparing the hash
// of the message payload to the MAC. Returns true if the message is unencrypted
// and false otherwise.
// the highest bit of the recpient ID is stored in the highest bit of the MAC
// field. This is accounted for and the id is reassembled, with a presumed user
// type
func IsUnencrypted(m format.Message) (bool, *id.ID) {

	expectedMac := makeUnencryptedMAC(m.GetContents())
	receivedMac := m.GetMac()
	idHighBit := (receivedMac[0] & 0b01000000) << 1
	receivedMac[0] &= macMask

	//return false if the message is not unencrypted
	if !bytes.Equal(expectedMac, receivedMac) {
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
func SetUnencrypted(m format.Message, uid *id.ID) {
	mac := makeUnencryptedMAC(m.GetContents())

	//copy in the high bit of the userID for storage
	mac[0] |= (uid[0] & 0b10000000) >> 1

	// Set the MAC
	m.SetMac(mac)

	//remove the type byte off of the userID and clear the highest bit so
	//it can be stored in the fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], uid[:format.KeyFPLen])
	fp[0] &= 0b01111111

	m.SetKeyFP(fp)
}

// returns the mac, fingerprint, and the highest byte
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
