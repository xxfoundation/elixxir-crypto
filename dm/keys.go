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
	_, ok := privKey.(*ecdh.PrivateKey)
	if !ok {
		jww.FATAL.Panic("private key must be x25519 ECDH")
	}

	myPrivKey, err := protocol.DH.ParsePrivateKey(privKey.Bytes())
	if err != nil {
		jww.FATAL.Panic(err)
	}

	return myPrivKey
}

func publicToNyquist(pubKey nike.PublicKey) dh.PublicKey {
	_, ok := pubKey.(*ecdh.PublicKey)
	if !ok {
		jww.FATAL.Panic("public key must be x25519 ECDH")
	}
	myPubKey, err := protocol.DH.ParsePublicKey(pubKey.Bytes())
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return myPubKey
}
