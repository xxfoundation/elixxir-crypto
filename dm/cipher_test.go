package dm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/elixxir/crypto/nike/ecdh"
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
