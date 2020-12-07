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
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

// the auth request fingerprint designates that a message is an auth request
// it is a fingerpint of a known public key. In the protocol it is hash(B1)

const authRequestFingerprintVector = "authRequestFingerprintVector"

//Sets the message as an authenticated channel creation message
func SetRequestFingerprint(m format.Message, partnerPublicKey *cyclic.Int) {

	//get the key hash
	keyHash := MakeRequestFingerprint(partnerPublicKey)

	//set the auth as the fingerprint
	m.SetKeyFP(keyHash)
}

//creates a valid auth request fingerprint from a public key
func MakeRequestFingerprint(publicKey *cyclic.Int) format.Fingerprint {
	// Create new hash
	//suppress because we just panic and a nil hash will panic anyhow
	h, _ := hash.NewCMixHash()
	// This will panic if we got an error in the line above, but does nothing
	// if it worked.
	h.Reset()

	// Hash the message payload
	h.Write(publicKey.Bytes())
	h.Write([]byte(authRequestFingerprintVector))
	keyHash := h.Sum(nil)

	//copy into a fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], keyHash)

	//set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111
	return fp
}
