////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package fingerprint includes code for identity fingerprints.
package fingerprint

import (
	"bytes"
	"crypto"
	_ "golang.org/x/crypto/blake2b"
)

// Size of the identity fingerprint defined in bits and converted to bytes for
// return type.
const identityFpSizeBits = 200
const identityFpSizeBytes = identityFpSizeBits / 8

// IdentityFP creates an identity fingerprint from encrypted message payload and
// recipient ID. The recipient ID is 200 bits and is the result of hashing the
// message payload with the marshalled ID.
func IdentityFP(encryptedMessagePayload []byte, preimage []byte) []byte {
	b2b := crypto.BLAKE2b_256.New()
	b2b.Write(GetMessageHash(encryptedMessagePayload))
	b2b.Write(preimage)
	return b2b.Sum(nil)[:identityFpSizeBytes]
}

// CheckIdentityFP checks if a received fingerprint is correct based on a
// message payload and recipient ID.
func CheckIdentityFP(receivedFP, encryptedMessagePayload []byte, preimage []byte) bool {
	identityFP := IdentityFP(encryptedMessagePayload, preimage)

	return bytes.Equal(identityFP, receivedFP)
}

// GetMessageHash returns a hash of the message payload.
func GetMessageHash(messagePayload []byte) []byte {
	b2b := crypto.BLAKE2b_256.New()
	b2b.Write(messagePayload)
	return b2b.Sum(nil)
}

// CheckIdentityFpFromMessageHash determines of the received fingerprint matches
// the hashed message and recipient ID.
func CheckIdentityFpFromMessageHash(receivedFP, messageHash []byte, preimage []byte) bool {
	b2b := crypto.BLAKE2b_256.New()
	b2b.Write(messageHash)
	b2b.Write(preimage)
	identityFP := b2b.Sum(nil)[:identityFpSizeBytes]

	return bytes.Equal(receivedFP, identityFP)
}
