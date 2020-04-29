////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package registration contains functions for generating data for registration.
// This includes base key and user ID generation
package registration

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/crypto/xx"
	"gitlab.com/elixxir/primitives/id"
)

// GenUserID generates the UserID based on his public key and a salt
// userID = CMixHash(pubkey||salt)
// Function panics if pubkey or salt are nil or contain empty byte slices
func GenUserID(pubKey *rsa.PublicKey, salt []byte) *id.ID {
	newId, err := xx.NewID(pubKey.PublicKey, salt, id.User)
	if err != nil {
		jww.FATAL.Panicf(err.Error())
	}
	return newId
}
