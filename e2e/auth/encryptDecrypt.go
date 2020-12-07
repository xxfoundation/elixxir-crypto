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
	"gitlab.com/elixxir/crypto/cyclic"
)

// Encrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func Encrypt(myPrivKey, partnerPubKey *cyclic.Int, salt, payload []byte,
	grp *cyclic.Group) (ecrPayload, mac []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Encrypt the payload
	ecrPayload = Crypt(authKey, vec, payload)

	// Generate the MAC
	mac = MakeMac(authKey, salt, ecrPayload)
	return ecrPayload, mac
}

// Decrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func Decrypt(myPrivKey, partnerPubKey *cyclic.Int, salt, ecrPayload, MAC []byte,
	grp *cyclic.Group) (success bool, payload []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Check if the mac if valid
	if !VerifyMac(authKey, salt, ecrPayload, MAC) {
		return false, nil
	}

	// Decrypt the payload
	payload = Crypt(authKey, vec, ecrPayload)

	return true, payload
}
