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

package auth

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	dh "gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/hash"
)

// Const string which gets hashed into the auth key
// to help indicate which operation has been done
var keygenVector = []byte("MakeAuthKey")

// MakeAuthKey generates a one-off key to be used to encrypt payloads
// for an authenticated channel
func MakeAuthKey(myPrivKey, partnerPubKey *cyclic.Int, salt []byte,
	grp *cyclic.Group) (Key []byte, Vector []byte) {
	// Generate the base key for the two users
	baseKey := dh.GenerateSessionKey(myPrivKey, partnerPubKey, grp)

	// Generate the hash function
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Could not get hash: %+v", err)
	}

	// Hash the base key, the salt and the vector together
	h.Write(baseKey.Bytes())
	h.Write(salt)
	h.Write([]byte(keygenVector))

	// Generate the auth key
	authKey := h.Sum(nil)

	// Reset the hash
	h.Reset()

	// Hash the auth key to generate the vector
	h.Write(authKey)
	authKeyHash := h.Sum(nil)

	// Generate a fingerprint of the vector
	h.Reset()

	return authKey, authKeyHash

}
