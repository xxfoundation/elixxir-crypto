////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"encoding/binary"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"io"
)

// Error messages.
const (
	cipherCannotDecryptErr  = "cannot decrypt ciphertext with secret: %+v"
	cipherCipherTextSizeErr = "ciphertext has length %d which is not block size %d"
	cipherInvalidBlockSize  = "cannot instantiate cipher with block size %d"
)

const (
	maximumPaddingLength = 2
)

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
func NewCipher(internalPassword, salt []byte, blockSize int,
	csprng io.Reader) (Cipher, error) {

	if blockSize == 0 {
		return nil, errors.Errorf(cipherInvalidBlockSize, blockSize)
	}

	// Generate key
	key := deriveDatabaseSecret(internalPassword, salt)

	return &cipher{
		secret:    key,
		blockSize: blockSize,
		rng:       csprng,
	}, nil
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
// if padding is necessary. If padding is necessary, the data will be
// formatted as such after padding: amountOfPadding | data | padding
// The amountOfPadding is the serialized uint64 byte data representing how long
// padding is in bytes.
func appendPadding(raw []byte, blockSize int) []byte {

	//
	difference := blockSize - len(raw)

	if difference >= 0 {

		// Amount of padding needed accounting for the prepending of the
		// length of the padding.
		amountOfPaddingNeeded := difference - maximumPaddingLength

		differenceSerialized := make([]byte, maximumPaddingLength)
		binary.PutUvarint(differenceSerialized, uint64(amountOfPaddingNeeded))

		padding := make([]byte, amountOfPaddingNeeded)
		raw = append(raw, padding...)
		raw = append(differenceSerialized, raw...)
	} else {

	}

	return raw
}

// discardPadding is a helper function which will return the plaintext with the
// padding removed.
func discardPadding(data []byte) []byte {
	// Starting from the tail and moving to the head, find the first index where
	// the byte data is non-zero at said index
	lengthOfPaddingSerialized, rest := data[:maximumPaddingLength], data[maximumPaddingLength:]
	lengthOfPadding, _ := binary.Uvarint(lengthOfPaddingSerialized)

	// The plaintext will be up to where padding starts
	startOfPadding := len(rest) - int(lengthOfPadding)
	plaintext := rest[:startOfPadding]

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
