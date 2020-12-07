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
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
)

// combinedHash generates a key from two user ids by appending hashes
// ordered by the larger user id
func combinedHash(userA, userB *id.ID, grp *cyclic.Group) *cyclic.Int {

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
func KeyGen(currentUser *id.ID, users []*id.ID,
	grp *cyclic.Group) []*cyclic.Int {
	keys := make([]*cyclic.Int, len(users))

	for i, user := range users {
		keys[i] = combinedHash(currentUser, user, grp)
	}

	return keys
}
