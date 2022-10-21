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
	plaintextTooLargeErr    = "plaintext too long (%d > max of %d)"
)

const (
	maximumPaddingLength = 2
)

// Cipher is the interface for storing encrypted channel messages into a
// database.
type Cipher interface {
	Encrypt(raw []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}

// cipher is an internal structure which adheres to the Cipher interface.
type cipher struct {
	secret    []byte
	blockSize int
	rng       io.Reader
}

// NewCipher is a constructor which builds a Cipher. PlaintextBlockSize is
// the maximum size of the plaintext. The ciphertext includes the
// nonce (24 bytes), and maximumPaddingLength bytes of overhead to encode the
// length of the plaintext.
func NewCipher(internalPassword, salt []byte, plaintextBlockSize int,
	csprng io.Reader) (Cipher, error) {

	if plaintextBlockSize == 0 {
		return nil, errors.Errorf(cipherInvalidBlockSize, plaintextBlockSize)
	}

	// Generate key
	key := deriveDatabaseSecret(internalPassword, salt)

	return &cipher{
		secret:    key,
		blockSize: plaintextBlockSize,
		rng:       csprng,
	}, nil
}

// Encrypt will encrypt the raw data. The standard entry length will be
// minimum length that the message will be padded. This allows no information
// about the encrypted message to be leaked at rest. To avoid padding the
// message, simply pass in zero (0) as the standard entry length.
func (c *cipher) Encrypt(plaintext []byte) ([]byte, error) {

	if len(plaintext) > c.blockSize {
		return nil, errors.Errorf(plaintextTooLargeErr, len(plaintext), c.blockSize)
	}

	plaintext, err := appendPadding(plaintext, c.blockSize, c.rng)
	if err != nil {
		return nil, err
	}

	// Generate cipher and nonce
	chaCipher := initChaCha20Poly1305(c.secret)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(c.rng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}

	// Encrypt data and return
	ciphertext := chaCipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt will decrypt the passed in encrypted value. If the plaintext was
// padded, the padding will be discarded at this level.
func (c *cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	// Generate cypher
	chaCipher := initChaCha20Poly1305(c.secret)

	nonceLen := chaCipher.NonceSize()
	if (len(ciphertext) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(ciphertext))
	}

	// The first nonceLen bytes of ciphertext are the nonce.
	nonce, encrypted := ciphertext[:nonceLen], ciphertext[nonceLen:]

	// Decrypt ciphertext
	paddedPlaintext, err := chaCipher.Open(nil, nonce, encrypted, nil)
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
func appendPadding(raw []byte, blockSize int, rng io.Reader) ([]byte, error) {
	// Generate result
	res := make([]byte, blockSize+maximumPaddingLength)

	// Serialize length of plaintext
	plaintextSize := len(raw)
	binary.PutUvarint(res[0:maximumPaddingLength], uint64(plaintextSize))

	// Put plaintext in result
	copy(res[maximumPaddingLength:], raw)

	// Add padding to the result from where plaintext ends
	padStart := maximumPaddingLength + plaintextSize
	n, err := rng.Read(res[padStart:])
	if err != nil {
		return nil, err
	}

	// Check that the correct amount of padding was read into the result
	padSize := blockSize - plaintextSize
	if n != padSize {
		return nil, errors.Errorf("short read (%d != %d)", n, padSize)
	}

	return res, nil
}

// discardPadding is a helper function which will return the plaintext with the
// padding removed.
func discardPadding(data []byte) []byte {
	plaintextSizeBytes := data[:maximumPaddingLength]
	plaintextSize, _ := binary.Uvarint(plaintextSizeBytes)

	return data[maximumPaddingLength:plaintextSize]
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
