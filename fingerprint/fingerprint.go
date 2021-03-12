////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package fingerprint includes code for identity fingerprints
package fingerprint

import (
	"bytes"
	"crypto"
	"gitlab.com/xx_network/primitives/id"
	_ "golang.org/x/crypto/blake2b"
)

// Size of the identiy fingerprint defined in bits & converted to bytes for return type
var identityFpSizeBits = 200
var identityFpSizeBytes = identityFpSizeBits / 8

// Create an identity fingerprint from encrypted message payload and recipient ID
// Recipient ID is 200 bits and is the result of hashing the message payload with the marshalled ID
func IdentityFP(encryptedMessagePayload []byte, recipientId *id.ID) ([]byte, error) {
	b2b := crypto.BLAKE2b_256.New()
	b2b.Write(encryptedMessagePayload)
	b2b.Write(recipientId.Marshal())
	return b2b.Sum(nil)[:identityFpSizeBytes], nil
}

// Check if a received fingerprint is correct based on message payload and ID
func CheckIdentityFP(receivedFP, encryptedMessagePayload []byte, recipientId *id.ID) (bool, error) {
	identityFP, err := IdentityFP(encryptedMessagePayload, recipientId)
	if err != nil {
		return false, err
	}
	return bytes.Compare(identityFP, receivedFP) == 0, nil
}
