////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"gitlab.com/elixxir/crypto/cyclic"
)

// Encrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func Encrypt(myPrivKey, partnerPubKey *cyclic.Int, payload []byte,
	grp *cyclic.Group) (ecrPayload, mac []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey,grp)

	// Encrypt the payload
	ecrPayload = Crypt(authKey, vec, payload)

	// Generate the MAC
	mac = MakeMac(authKey, ecrPayload)
	return ecrPayload, mac
}

// Decrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func Decrypt(myPrivKey, partnerPubKey *cyclic.Int, ecrPayload, MAC []byte,
	grp *cyclic.Group) (success bool, payload []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey, grp)

	// Check if the mac if valid
	if !VerifyMac(authKey, ecrPayload, MAC) {
		return false, nil
	}

	// Decrypt the payload
	payload = Crypt(authKey, vec, ecrPayload)

	return true, payload
}
