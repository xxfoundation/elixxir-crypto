////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
)

// Error messages.
const (
	// newReceptionID
	errNewID = "[BCAST] Failed to create new reception ID for broadcast " +
		"channel: %+v"

	// newReceptionIdSalt
	errNewReceptionIdSaltHash = "[BCAST] Failed to create new hash for salt " +
		"for symmetric broadcast channel %q: %+v"
)

const receptionIdSaltConst = "symmetricBroadcastReceptionIdSalt"

// newReceptionID generates a new reception ID used for broadcast channels. It
// is a hash of the RSA public key and the reception ID salt generated via
// newReceptionIdSalt.
func newReceptionID(name, description string, symmetricSalt []byte,
	rsaPubKey *rsa.PublicKey) *id.ID {
	receptionIdSalt := newReceptionIdSalt(symmetricSalt, name, description)

	receptionID, err := xx.NewID(rsaPubKey, receptionIdSalt, id.User)
	if err != nil {
		jww.FATAL.Panicf(errNewID, err)
	}

	return receptionID
}

// newReceptionIdSalt generates a new salt that is used to generate a reception
// ID for a Symmetric broadcast channel. The salt is a hash of the symmetric
// salt, name, and description. This allows a recipient of an ID to verify it is
// well-formed and does not collide with other Symmetric channels.
func newReceptionIdSalt(symmetricSalt []byte, name, description string) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(errNewReceptionIdSaltHash, name, err)
	}

	h.Write(symmetricSalt)
	h.Write([]byte(name))
	h.Write([]byte(description))
	h.Write([]byte(receptionIdSaltConst))

	return h.Sum(nil)
}
