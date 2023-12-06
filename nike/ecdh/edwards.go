////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ecdh

import (
	"crypto/ed25519"

	"gitlab.com/elixxir/crypto/nike"
)

// Edwards2EcdhNikePublicKey converts a public key from a signing key to a NIKE
// (key exchange compatible) version of the public key.
func Edwards2EcdhNikePublicKey(
	publicEdwardsKey ed25519.PublicKey) nike.PublicKey {
	publicKey := ECDHNIKE.NewEmptyPublicKey()
	publicKey.(*PublicKey).FromEdwards(publicEdwardsKey)
	return publicKey
}

// EcdhNike2EdwardsPublicKey converts a public key from a signing key to a NIKE
// (key exchange compatible) version of the public key.
func EcdhNike2EdwardsPublicKey(publicKey nike.PublicKey) ed25519.PublicKey {
	p := ed25519.PublicKey(publicKey.Bytes())
	return p
}

// Edwards2EcdhNikePrivateKey converts a private key from a signing
// key to a NIKE (key exchange compatible) version of the private
// key.
func Edwards2EcdhNikePrivateKey(
	privateEdwardsKey ed25519.PrivateKey) nike.PrivateKey {
	privateKey := ECDHNIKE.NewEmptyPrivateKey()
	privateKey.(*PrivateKey).FromEdwards(privateEdwardsKey)
	return privateKey
}
