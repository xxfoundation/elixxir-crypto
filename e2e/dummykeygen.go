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
	"bytes"
	"gitlab.com/xx_network/crypto/cyclic"
	"gitlab.com/xx_network/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
	goHash "hash"
)

// combinedHash generates a key from two user ids by appending hashes
// ordered by the larger user id
func combinedHash(userA, userB *id.ID, grp *cyclic.Group) *cyclic.Int {

	// Create combined key by appending the smaller slice
	var combKey []byte
	as := userA.Bytes()
	bs := userB.Bytes()
	if bytes.Compare(as, bs) >= 0 {
		combKey = append(userA.Bytes(), userB.Bytes()...)
	} else {
		combKey = append(userB.Bytes(), userA.Bytes()...)
	}

	hashFunc := func() goHash.Hash {
		h, _ := hash.NewCMixHash()
		return h
	}
	expKey := hash.ExpandKey(hashFunc, grp, combKey, grp.NewInt(1))

	return expKey

}

// KeyGen generates keys for all combinations of users for the current user
func KeyGen(currentUser *id.ID, users []*id.ID,
	grp *cyclic.Group) []*cyclic.Int {
	keys := make([]*cyclic.Int, len(users))

	for i, user := range users {
		keys[i] = combinedHash(currentUser, user, grp)
	}

	return keys
}
