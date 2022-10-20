////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"io"
)

// Error messages.
const (
	cipherCannotDecryptErr  = "cannot decrypt ciphertext with secret: %+v"
	cipherCipherTextSizeErr = "ciphertext has length %d which is not block size %d"
)

var padding = []byte{52, 13}

// Cipher is the interface for storing encrypted channel messages into a
// database.
type Cipher interface {
	Encrypt(raw []byte) []byte
	Decrypt(encrypted []byte) ([]byte, error)
}

// cipher is an internal structure which adheres to the Cipher interface.
type cipher struct {
	secret    []byte
	blockSize int
	rng       io.Reader
}

// NewCipher is a constructor which builds a Cipher.
func NewCipher(internalPassword, salt []byte, blockSize int, csprng io.Reader) Cipher {

	// Generate key
	key := deriveDatabaseSecret(internalPassword, salt)

	return &cipher{
		secret:    key,
		blockSize: blockSize,
		rng:       csprng,
	}
}

// Encrypt will encrypt the raw data. The standard entry length will be
// minimum length that the message will be padded. This allows no information
// about the encrypted message to be leaked at rest. To avoid padding the
// message, simply pass in zero (0) as the standard entry length.
func (c *cipher) Encrypt(plaintext []byte) []byte {
	plaintext = appendPadding(plaintext, c.blockSize)

	// Generate cipher and nonce
	chaCipher := initChaCha20Poly1305(c.secret)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(c.rng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}

	// Encrypt data and return
	ciphertext := chaCipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

// Decrypt will decrypt the passed in encrypted value. If the plaintext was
// padded, the padding will be discarded at this level.
func (c *cipher) Decrypt(encrypted []byte) ([]byte, error) {
	// Generate cypher
	chaCipher := initChaCha20Poly1305(c.secret)

	nonceLen := chaCipher.NonceSize()
	if (len(encrypted) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(encrypted))
	}

	// The first nonceLen bytes of ciphertext are the nonce.
	nonce, ciphertext := encrypted[:nonceLen], encrypted[nonceLen:]

	// Decrypt ciphertext
	paddedPlaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf(cipherCannotDecryptErr, err)
	}

	// Remove padding from plaintext
	plaintext := discardPadding(paddedPlaintext)

	return plaintext, nil

}

// appendPadding is a helper function which adds padding to the raw plaintext,
// if padding is necessary and specified.
func appendPadding(raw []byte, standardEntryLength int) []byte {
	if standardEntryLength == 0 {
		jww.WARN.Printf("Standard entry length is zero, will not pad raw data!")
	} else {
		// Pad raw data if data is less than the standard length
		difference := standardEntryLength - len(raw)

		if difference > 0 {
			dataToAppend := make([]byte, difference)
			raw = append(raw, dataToAppend...)
		}
	}

	return raw
}

// discardPadding is a helper function which will return the plaintext with the
// padding removed.
func discardPadding(data []byte) []byte {
	// Starting from the tail and moving to the head, find the first index where
	// the byte data is non-zero at said index
	startOfPadding := len(data)
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != byte(0) {
			break
		}

		startOfPadding = i

	}

	// The plaintext will be up to where padding starts
	plaintext := data[:startOfPadding]

	return plaintext
}

// deriveDatabaseSecret is a helper function which will generate the key for
// encryption/decryption of
func deriveDatabaseSecret(password, salt []byte) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to generate cMix hash: %+v", err)
	}
	h.Write(password)
	h.Write(salt)
	return h.Sum(nil)
}
