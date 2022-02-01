///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"crypto/rand"
	"encoding/hex"
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

func TestDecryptPrecannedCiphertext(t *testing.T) {
	keyStr := "a0759e10811c9d3057ef4dfa02fb61b7dea6d47fb4291d2900dbe985c29f5cf1"
	plaintextStr := "0a1e7a04bb33b469072d927cd6ebbc38d7b193a0889cbc3492325aca2353fd8418ebc7ad6a023ce3ab70869c21356a74006e94535e56358d7bd9ea8f9899e04ff36e7942c2a2fdc52ddbc4842db0cae686ee6c228acdec636c35252723a9bdfd09dafee09ff11e5c0d1b06a3bd38e331c17347d8e6f2f32b9ed00a133c343df4a9f5d3b19bbdca78bd8aaa0551e1386c562e83d45bc9b3"
	ciphertextStr := "b24392adb94cc849cd595e8a9d919baa5e6ab23391bbde74537a5825c224592835ebed06c470f73709fd7156c34103fbffb7598cd39631f362eae5bf283a7310c45cbb8109e18a7be3e1d676dd8729b4f7820492256c01095417b9acc36b358735f650799e2763eafbc7fd71d85604b3a81e47f17ef5de26a239becdc8381e8aa3fc91f93ac636a53dfb3d70e77f2b4a3618f20b9dc4137c507de43a4ca78659dd6be8a4cdef78cf0baa0c6a4e9738c62a06ae9b05c3201bd64022930a2986"

	key, err := hex.DecodeString(keyStr)
	require.NoError(t, err)

	plaintext, err := hex.DecodeString(plaintextStr)
	require.NoError(t, err)

	ciphertext, err := hex.DecodeString(ciphertextStr)
	require.NoError(t, err)

	plaintext2, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, plaintext2)
}
