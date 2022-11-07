////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/yawning/nyquist.git"
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
	panicOnError(err)

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

// handleErrorOnNoise is a helper function which will handle error on the
// Noise protocol's Encrypt/Decrypt. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func handleErrorOnNoise(hs *nyquist.HandshakeState, err error) {
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			jww.FATAL.Panic(status.Err)
		}
	case nil:
	default:
		jww.FATAL.Panic(err)
	}

}

// panicOnError is a helper function which will panic if the
// error is nil. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnError(err error) {
	if err != nil {
		jww.FATAL.Panic(err)
	}
}
