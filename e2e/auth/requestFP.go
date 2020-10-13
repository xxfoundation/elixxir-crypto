////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	jww "github.com/spf13/jwalterweatherman"
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
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %+v", err)
	}

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
