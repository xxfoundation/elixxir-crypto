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
func Encrypt(myPrivKey, partnerPubKey *cyclic.Int, salt, payload []byte,
	grp *cyclic.Group) (ecrPayload, mac []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Encrypt the payload
	ecrPayload = Crypt(authKey, vec, payload)

	// Generate the MAC
	mac = MakeMac(partnerPubKey, authKey, salt, ecrPayload)
	return ecrPayload, mac
}

// Decrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func Decrypt(myPrivKey, partnerPubKey *cyclic.Int, salt, ecrPayload, MAC []byte,
	grp *cyclic.Group) (success bool, payload []byte) {

	// Generate the base key
	authKey, vec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Check if the mac if valid
	if !VerifyMac(partnerPubKey, authKey, salt, ecrPayload, MAC) {
		return false, nil
	}

	// Decrypt the payload
	payload = Crypt(authKey, vec, ecrPayload)

	return true, payload
}
