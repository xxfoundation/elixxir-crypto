////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package registration contains functions for generating data for registration.
// This includes base key and user ID generation
package registration

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/primitives/id"
)

// GenUserID generates the UserID based on his public key and a salt
// userID = CMixHash(pubkey||salt)
// Function panics if pubkey or salt are nil or contain empty byte slices
func GenUserID(pubKey *rsa.PublicKey, salt []byte) *id.User {
	if pubKey == nil || salt == nil {
		jww.ERROR.Panicf("PubKey and/or Salt are nil")
	}
	pubBytes := pubKey.N.Bytes()

	pubIntBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pubIntBytes, uint64(pubKey.E))
	pubBytes = append(pubBytes, pubIntBytes...)

	if len(pubBytes) == 0 || len(salt) == 0 {
		jww.ERROR.Panicf("PubKey and/or Salt are empty")
	}
	h, _ := hash.NewCMixHash()
	h.Write(pubBytes)
	h.Write(salt)
	userID := id.NewUserFromBytes(h.Sum(nil))
	return userID
}
