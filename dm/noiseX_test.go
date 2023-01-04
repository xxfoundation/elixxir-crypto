////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/rand"
	"testing"

	jww "github.com/spf13/jwalterweatherman"
	"github.com/stretchr/testify/require"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/yawning/nyquist.git"
	"gitlab.com/yawning/nyquist.git/cipher"
	"gitlab.com/yawning/nyquist.git/dh"
	"gitlab.com/yawning/nyquist.git/hash"
	"gitlab.com/yawning/nyquist.git/pattern"
)

func TestNoise(t *testing.T) {
	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	require.NoError(t, err)

	protocol2 := &nyquist.Protocol{
		Pattern: pattern.X,
		DH:      dh.X25519,
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}
	require.Equal(t, protocol, protocol2)

	aliceStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	bobStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	aliceCfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  aliceStatic,
		RemoteStatic: bobStatic.Public(),
		IsInitiator:  true,
	}

	bobCfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  bobStatic,
		RemoteStatic: aliceStatic.Public(),
		IsInitiator:  false,
	}

	aliceHs, err := nyquist.NewHandshake(aliceCfg)
	require.NoError(t, err)

	bobHs, err := nyquist.NewHandshake(bobCfg)
	require.NoError(t, err)

	require.True(t, aliceCfg.Protocol.Pattern.IsOneWay())
	require.True(t, bobCfg.Protocol.Pattern.IsOneWay())

	defer aliceHs.Reset()
	defer bobHs.Reset()

	aliceSs := aliceHs.SymmetricState()
	require.NotNil(t, aliceSs)
	aliceCs := aliceSs.CipherState()
	require.NotNil(t, aliceCs)

	alicePlaintextE := []byte("Hello, I am a message.")
	aliceMsg1, err := aliceHs.WriteMessage(nil, alicePlaintextE)

	t.Logf("alicePlaintextE eln %d", len(alicePlaintextE))
	t.Logf("aliceMsg1 len %d", len(aliceMsg1))
	t.Logf("noise overhead is %d", len(aliceMsg1)-len(alicePlaintextE))

	switch err {
	case nyquist.ErrDone:
		status := aliceHs.GetStatus()
		require.Equal(t, status.Err, nyquist.ErrDone)
	case nil:
	default:
		require.NoError(t, err)
	}

	bobRecv, err := bobHs.ReadMessage(nil, aliceMsg1)

	switch err {
	case nyquist.ErrDone:
		status := bobHs.GetStatus()
		require.Equal(t, status.Err, nyquist.ErrDone)
	case nil:
	default:
		require.NoError(t, err)
	}

	require.Equal(t, bobRecv, alicePlaintextE)

	aliceStatus := aliceHs.GetStatus()
	bobStatus := bobHs.GetStatus()

	require.Equal(t, aliceStatus.HandshakeHash, bobStatus.HandshakeHash)
	require.Equal(t, aliceStatus.LocalEphemeral.Bytes(), bobStatus.RemoteEphemeral.Bytes())
	require.Equal(t, aliceStatus.RemoteStatic.Bytes(), bobStatic.Public().Bytes())
	require.Equal(t, bobStatus.RemoteStatic.Bytes(), aliceStatic.Public().Bytes())
}

// TestCrossingWires tests that if you encrypt a message using Encrypt,
// DecryptSelf will fail to decrypt it.
func TestCrossingWires(t *testing.T) {
	message1 := []byte("i am a message")
	rng := csprng.NewSystemRNG()

	alicePrivKey, _ := ecdh.ECDHNIKE.NewKeypair(rng)
	bobPrivKey, bobPubKey := ecdh.ECDHNIKE.NewKeypair(rng)

	ciphertext := Cipher.Encrypt(message1, alicePrivKey, bobPubKey, rng,
		10000)

	_, _, err := Cipher.DecryptSelf(ciphertext, bobPrivKey)
	if err == nil {
		t.Fatalf("DecryptSelf should fail when passed ciphertext from encrypt.")
	}

}

func TestNoisEncryptDecrypt(t *testing.T) {
	message1 := []byte("i am a message")
	rng := csprng.NewSystemRNG()

	//alicePrivKey, _ := ecdh.ECDHNIKE.NewKeypair()
	bobPrivKey, bobPubKey := ecdh.ECDHNIKE.NewKeypair(rng)

	noiseCipher := &noiseX{}

	ciphertext := noiseCipher.Encrypt(message1, bobPubKey,
		rng)

	message2, err := noiseCipher.Decrypt(ciphertext,
		bobPrivKey)
	require.NoError(t, err)

	require.Equal(t, message1, message2)
}

func wrongEncrypt(plaintext []byte, myStatic nike.PrivateKey,
	partnerStaticPubKey nike.PublicKey) []byte {
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
