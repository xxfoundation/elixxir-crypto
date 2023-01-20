////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	cryptoCipher "crypto/cipher"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/backup"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

// Error messages.
const (
	// decryptIdentity
	readNonceLenErr        = "read %d bytes, too short to decrypt"
	decryptWithPasswordErr = "cannot decrypt with password: %+v"

	// makeSalt
	readSaltErr     = "could not read RNG for salt: %+v"
	saltNumBytesErr = "expected %d bytes for salt, found %d bytes"
)

// encryptIdentity encrypts the data for an Identity using XChaCha20-Poly1305.
// The resulting encrypted data has the nonce prepended to it.
func encryptIdentity(data, key []byte, csprng io.Reader) []byte {
	chaCipher := initChaCha20Poly1305(key)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(csprng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}
	ciphertext := chaCipher.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decryptIdentity decrypts the Identity using XChaCha20-Poly1305.
func decryptIdentity(data, key []byte) ([]byte, error) {
	chaCipher := initChaCha20Poly1305(key)
	nonceLen := chaCipher.NonceSize()
	if (len(data) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(data))
	}

	// The first nonceLen bytes of ciphertext are the nonce.
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf(decryptWithPasswordErr, err)
	}
	return plaintext, nil
}

// initChaCha20Poly1305 returns a XChaCha20-Poly1305 cipher.AEAD that uses the
// given password hashed into a 256-bit key.
func initChaCha20Poly1305(key []byte) cryptoCipher.AEAD {
	pwHash := blake2b.Sum256(key)
	chaCipher, err := chacha20poly1305.NewX(pwHash[:])
	if err != nil {
		jww.FATAL.Panicf("Could not init XChaCha20Poly1305 mode: %+v", err)
	}

	return chaCipher
}

// deriveKey derives a key from a user supplied password and a salt via the
// Argon2 algorithm.
func deriveKey(password string, salt []byte, params backup.Params) []byte {
	return argon2.IDKey([]byte(password), salt,
		params.Time, params.Memory, params.Threads, keyLen)
}

// makeSalt generates a salt used for key generation.
func makeSalt(csprng io.Reader) ([]byte, error) {
	b := make([]byte, saltLen)
	size, err := csprng.Read(b)
	if err != nil {
		return nil, errors.Errorf(readSaltErr, err)
	} else if size != saltLen {
		return nil, errors.Errorf(saltNumBytesErr, saltLen, size)
	}

	return b, nil
}
