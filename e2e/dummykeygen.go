////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/id"
)

// combinedHash generates a key from two user ids by appending hashes
// ordered by the larger user id
func combinedHash(userA *id.User, userB *id.User, grp *cyclic.Group) *cyclic.Int {

	h, _ := hash.NewCMixHash()

	// Create combined key by appending the smaller slice
	var combKey []byte
	as := userA.Bytes()
	bs := userB.Bytes()
	if bytes.Compare(as, bs) >= 0 {
		combKey = append(userA.Bytes(), userB.Bytes()...)
	} else {
		combKey = append(userB.Bytes(), userA.Bytes()...)
	}

	expKey := hash.ExpandKey(h, grp, combKey, grp.NewInt(1))

	return expKey

}

// KeyGen generates keys for all combinations of users for the current user
func KeyGen(currentUser *id.User, users []*id.User, grp *cyclic.Group) []*cyclic.Int {
	keys := make([]*cyclic.Int, len(users))

	for i, user := range users {
		keys[i] = combinedHash(currentUser, user, grp)
	}

	return keys
}
