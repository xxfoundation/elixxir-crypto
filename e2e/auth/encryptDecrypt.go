////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"gitlab.com/elixxir/crypto/cyclic"
	dh "gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/format"
)

// Encrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func AuthPayloadEncrypt(myPrivKey, partnerPubKey *cyclic.Int, vector,
	salt, payload []byte, grp *cyclic.Group) (ecrPayload, mac []byte,
	fpVector format.Fingerprint) {

	// Generate the base key
	baseKey := dh.GenerateSessionKey(myPrivKey, partnerPubKey, grp)

	ecrPayload, fpVector = Crypt(baseKey.Bytes(), vector, payload)

	mac = MakeMac(partnerPubKey, baseKey.Bytes(), salt, ecrPayload)
	return ecrPayload, mac, fpVector
}

// Decrypts the payload for use in authenticated channels and provides a MAC
// on this encrypted payload
func AuthPayloadDecrypt(myPrivKey, partnerPubKey *cyclic.Int, vector,
	salt, ecrPayload, MAC []byte, grp *cyclic.Group) (success bool, payload []byte,
	fpVector format.Fingerprint) {

	// Generate the base key
	baseKey := dh.GenerateSessionKey(myPrivKey, partnerPubKey, grp)

	// Check if the mac if valid
	if !VerifyMac(partnerPubKey, baseKey.Bytes(), salt, ecrPayload, MAC) {
		return false, nil, format.Fingerprint{}
	}

	// Decrypt the payload
	payload, fpVector = Crypt(baseKey.Bytes(), vector, ecrPayload)

	return true, payload, fpVector
}
