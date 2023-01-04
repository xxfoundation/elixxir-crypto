////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/yawning/nyquist.git/dh"

	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
)

func privateToNyquist(privKey nike.PrivateKey) dh.Keypair {
	p, ok := privKey.(*ecdh.PrivateKey)
	panicOnFailureToCast(ok, "private key")

	myPrivKey, err := protocol.DH.ParsePrivateKey(p.MontgomeryBytes())
	panicOnError(err)

	return myPrivKey
}

func publicToNyquist(pubKey nike.PublicKey) dh.PublicKey {
	p, ok := pubKey.(*ecdh.PublicKey)
	panicOnFailureToCast(ok, "public key")
	myPubKey, err := protocol.DH.ParsePublicKey(p.MontgomeryBytes())
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return myPubKey
}

func panicOnFailureToCast(ok bool, keyType string) {
	if !ok {
		jww.FATAL.Panicf("%s must be x25519 ECDH", keyType)
	}
}
