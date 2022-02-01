///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/stretchr/testify/require"

	"gitlab.com/xx_network/crypto/csprng"
)

func TestDecryptWithBadKeySize(t *testing.T) {

	plaintext := make([]byte, chacha20poly1305.NonceSize+chacha20poly1305.Overhead+123)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	ciphertext, err := Encrypt(csprng.NewSystemRNG(), plaintext, key)
	require.NoError(t, err)

	_, err = Decrypt(ciphertext, key[:len(key)-2])
	require.Error(t, err)
}

func TestEncryptWithBadKeySize(t *testing.T) {

	plaintext := make([]byte, chacha20poly1305.NonceSize+chacha20poly1305.Overhead+123)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	_, err = Encrypt(csprng.NewSystemRNG(), plaintext, key[:len(key)-2])
	require.Error(t, err)
}

func TestDecryptBadCiphertextSize(t *testing.T) {

	plaintext := make([]byte, chacha20poly1305.NonceSize+chacha20poly1305.Overhead+123)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	ciphertext, err := Encrypt(csprng.NewSystemRNG(), plaintext, key)
	require.NoError(t, err)

	_, err = Decrypt(ciphertext[:chacha20poly1305.NonceSize], key)
	require.Error(t, err)
}

func TestEncryptAndDecrypt(t *testing.T) {

	plaintext := make([]byte, chacha20poly1305.NonceSize+chacha20poly1305.Overhead+123)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	ciphertext, err := Encrypt(csprng.NewSystemRNG(), plaintext, key)
	require.NoError(t, err)

	plaintext2, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, plaintext2)
}
