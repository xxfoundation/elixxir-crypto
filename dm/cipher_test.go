////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"testing"

	jww "github.com/spf13/jwalterweatherman"
	"github.com/stretchr/testify/require"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/yawning/nyquist.git"
)

func TestEncryptDecrypt(t *testing.T) {
	message1 := []byte("i am a message")

	alicePrivKey, alicePubKey := ecdh.ECDHNIKE.NewKeypair()
	bobPrivKey, bobPubKey := ecdh.ECDHNIKE.NewKeypair()

	ciphertext := Cipher.Encrypt(message1, alicePrivKey, bobPubKey)

	message2, err := Cipher.Decrypt(ciphertext, bobPrivKey, alicePubKey)
	require.NoError(t, err)

	require.Equal(t, message1, message2)
}

func wrongEncrypt(plaintext []byte, myStatic nike.PrivateKey, partnerStaticPubKey nike.PublicKey) []byte {
	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     []byte{9, 9},
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  true,
	}
	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	defer hs.Reset()
	ciphertext, err := hs.WriteMessage(nil, plaintext)
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
	return ciphertext
}

func TestWrongPrologue(t *testing.T) {
	message1 := []byte("i am a message")

	alicePrivKey, alicePubKey := ecdh.ECDHNIKE.NewKeypair()
	bobPrivKey, bobPubKey := ecdh.ECDHNIKE.NewKeypair()

	ciphertext := wrongEncrypt(message1, alicePrivKey, bobPubKey)

	_, err := Cipher.Decrypt(ciphertext, bobPrivKey, alicePubKey)
	require.Error(t, err)
}
