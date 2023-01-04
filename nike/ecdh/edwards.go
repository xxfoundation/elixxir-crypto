////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ecdh

import (
	"crypto/ed25519"

	"gitlab.com/elixxir/crypto/nike"
)

// Edwards2ECDHNIKEPublicKey converts a public key from a signing key to a NIKE
// (key exchange compatible) version of the the public key.
func Edwards2ECDHNIKEPublicKey(
	publicEdwardsKey *ed25519.PublicKey) nike.PublicKey {
	publicKey := ECDHNIKE.NewEmptyPublicKey()
	publicKey.(*PublicKey).FromEdwards(*publicEdwardsKey)
	return publicKey
}

// nike2EdwardsPublicKey converts a public key from a signing key to a NIKE
// (key exchange compatible) version of the the public key.
func ECDHNIKE2EdwardsPublicKey(publicKey nike.PublicKey) *ed25519.PublicKey {
	p := ed25519.PublicKey(publicKey.Bytes())
	return &p
}

// Edwards2ECDHNIKEPrivateKey converts a private key from a signing
// key to a NIKE (key exchange compatible) version of the the private
// key.
func Edwards2ECDHNIKEPrivateKey(
	privateEdwardsKey *ed25519.PrivateKey) nike.PrivateKey {
	privateKey := ECDHNIKE.NewEmptyPrivateKey()
	privateKey.(*PrivateKey).FromEdwards(*privateEdwardsKey)
	return privateKey
}
