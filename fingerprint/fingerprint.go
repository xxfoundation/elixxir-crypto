////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package fingerprint includes code for identity fingerprints
package fingerprint

import (
	"crypto"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
	_ "golang.org/x/crypto/blake2b"
)

// Create an identity fingerprint from encrypted message payload and recipient ID
// Recipient ID is 200 bits and is the result of hashing the message payload with the marshalled ID
func IdentityFP(encryptedMessagePayload []byte, recipientId *id.ID) ([]byte, error) {
	fp := [25]byte{}
	b2b := crypto.BLAKE2b_256.New()
	_, err := b2b.Write(encryptedMessagePayload)
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to write encrypted message payload %+v to hash",
			encryptedMessagePayload)
	}
	_, err = b2b.Write(recipientId.Marshal())
	if err != nil {
		return nil, errors.WithMessagef(err, "Failed to write recipient ID %+v to hash",
			recipientId.Marshal())
	}
	_ = copy(fp[:], b2b.Sum(nil))
	return fp[:], nil
}
