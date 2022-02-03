///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"gitlab.com/xx_network/crypto/csprng"
)

func Encrypt(rand csprng.Source, plaintext, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("Backup.Store: incorrect key size")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	size, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	if size != chacha20poly1305.NonceSizeX {
		return nil, errors.New("csprng returned wrong number of bytes")
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func Decrypt(blob, key []byte) ([]byte, error) {

	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("Backup.Store: incorrect key size")
	}

	if len(blob) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead+1 {
		return nil, errors.New("ciphertext size is too small")
	}

	nonceLen := chacha20poly1305.NonceSizeX
	nonce, ciphertext := blob[:nonceLen], blob[nonceLen:]

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
