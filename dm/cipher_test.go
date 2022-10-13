package dm

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/nyquist.git"
)

func TestEncryptDecrypt(t *testing.T) {

	message1 := []byte("i am a message")

	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	require.NoError(t, err)

	aliceStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	bobStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	ciphertext := Cipher.Encrypt(message1, &PrivateKey{
		privateKey: aliceStatic,
	}, &PublicKey{
		publicKey: bobStatic.Public(),
	})

	message2, err := Cipher.Decrypt(ciphertext, &PrivateKey{
		privateKey: bobStatic,
	}, &PublicKey{
		publicKey: aliceStatic.Public(),
	})
	require.NoError(t, err)

	require.Equal(t, message1, message2)
}
