////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
)

func TestEncryptDecrypt(t *testing.T) {
	message1 := []byte("i am a message")

	rng := csprng.NewSystemRNG()

	alicePrivKey, expAlicePubKey := ecdh.ECDHNIKE.NewKeypair(rng)
	bobPrivKey, bobPubKey := ecdh.ECDHNIKE.NewKeypair(rng)

	// Encrypt for Bob from Alice
	ciphertext := Cipher.Encrypt(message1, alicePrivKey, bobPubKey,
		rng, 10000)

	require.Equal(t, 10000, len(ciphertext))

	alicePubKey, message2, err := Cipher.Decrypt(ciphertext, bobPrivKey)
	require.NoError(t, err)

	require.Equal(t, len(message1), len(message2))

	require.Equal(t, expAlicePubKey.Bytes(), alicePubKey.Bytes())

	require.Equal(t, message1, message2)
}
