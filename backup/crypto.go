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
)

func Encrypt(plaintext, key, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("Backup.Store: incorrect key size")
	}

	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("Backup.Store: incorrect nonce size")
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

func Decrypt(blob, key []byte) ([]byte, error) {

	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("Backup.Store: incorrect key size")
	}

	if len(blob) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead+1 {
		return nil, errors.New("ciphertext size is too small")
	}

	offset := chacha20poly1305.NonceSizeX
	nonce := blob[:offset]
	ciphertext := blob[offset:]

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
