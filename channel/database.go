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

const DatabaseSecretSize = 32

// Crypt is the interface for storing encrypted channel messages into a
// database.
type Crypt interface {
	Encrypt(raw []byte, standardEntryLength int) []byte
	Decrypt(encrypted []byte) ([]byte, error)
	GetSalt() []byte
}

// crypt is an internal structure which adheres to the Crypt interface.
type crypt struct {
	password []byte
	salt     []byte
	rng      io.Reader
}

// NewCrypt is a constructor which builds a Crypt. This will generate a
// salt that will be used for key construction. This can be retrieved using
// Crypt.GetSalt.
func NewCrypt(internalPassword []byte, csprng io.Reader) Crypt {

	salt := make([]byte, DatabaseSecretSize)
	if _, err := io.ReadFull(csprng, salt); err != nil {
		jww.FATAL.Panicf("Could not generate salt %+v", err)
	}

	return &crypt{
		password: internalPassword,
		salt:     salt,
		rng:      csprng,
	}
}

// Encrypt will encrypt the raw data. The standard entry length will be
// minimum length that the message will be padded. This allows no information
// about the encrypted message to be leaked at rest. To avoid padding the
// message, simply pass in zero (0) as the standard entry length.
func (c *crypt) Encrypt(plaintext []byte, blockSize int) []byte {
	plaintext = appendPadding(plaintext, blockSize)

	// Generate key
	key := c.deriveDatabaseSecret()

	// Generate cipher and nonce
	chaCipher := initChaCha20Poly1305(key)
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
func (c *crypt) Decrypt(encrypted []byte) ([]byte, error) {

	// Generate key
	key := c.deriveDatabaseSecret()

	// Generate cypher
	chaCipher := initChaCha20Poly1305(key)

	nonceLen := chaCipher.NonceSize()
	if (len(encrypted) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(encrypted))
	}

	// The first nonceLen bytes of ciphertext are the nonce.
	nonce, ciphertext := encrypted[:nonceLen], encrypted[nonceLen:]
	paddedPlaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf(decryptWithPasswordErr, err)
	}

	plaintext := discardPadding(paddedPlaintext)

	return plaintext, nil

}

// GetSalt retrieves the salt generated in the NewCrypt call.
func (c *crypt) GetSalt() []byte {
	return c.salt
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
func (c *crypt) deriveDatabaseSecret() []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to generate cMix hash: %+v", err)
	}
	h.Write(c.password)
	h.Write(c.salt)
	return h.Sum(nil)
}
