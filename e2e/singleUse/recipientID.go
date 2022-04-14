///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
)

// NewRecipientID generates the recipient ID for a single-use sender. The ID is
// generated from the hash of the unencrypted transmission payload. The
// unencryptedPayload must contain a nonce to prevent collision on the same
// message being sent multiple times.
func NewRecipientID(pubKey *cyclic.Int, unencryptedPayload []byte) *id.ID {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[SU] Failed to create new hash for single-use "+
			"communication recipient ID: %+v", err)
	}

	// Hash the public key and unencrypted payload
	h.Write(pubKey.Bytes())
	h.Write(unencryptedPayload)

	// Get hash bytes
	rid := &id.ID{}
	copy(rid[:], h.Sum(nil))

	// Set the ID type to user
	rid.SetType(id.User)

	return rid
}
