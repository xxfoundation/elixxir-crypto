package dmnoise

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

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
