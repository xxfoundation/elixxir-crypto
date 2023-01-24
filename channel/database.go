////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"encoding/binary"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"io"
)

// Error messages.
const (
	// NewCipher
	cipherInvalidBlockSizeErr = "block size must be at least 1 byte; received %d bytes"

	// cipher.Encrypt
	plaintextTooLargeErr = "plaintext must be %d bytes or less; received %d bytes"
	generateNoncePanic   = "Could not generate nonce for channel database message encryption: %+v"

	// cipher.Decrypt
	cipherCannotDecryptErr = "cannot decrypt ciphertext with secret: %+v"

	// appendPadding
	shortPaddingReadErr = "short read (%d != %d)"
)

const (
	// lengthOfOverhead is the space allocated, in bytes, to represent the size
	// of the plaintext. This will be added to the padded plaintext prior to
	// encryption.
	//
	// Note that plaintext with a length that cannot be expressed in this
	// byte-size will result in an error.
	lengthOfOverhead = 2
)

// Cipher manages the encryption and decryption of channel messages that are
// inserted into or read from the database.
type Cipher interface {
	// Encrypt encrypts the raw data. The returned ciphertext includes the nonce
	// (24 bytes) and the encrypted plaintext (with possible padding, if
	// needed).
	//
	// Prior to encrypting the plaintext, a padding will be appended if it is
	// shorter than the pre-defined block size passed into NewCipher.
	//
	// If the plaintext is longer than the block size, then Encrypt will return
	// an error.
	Encrypt(plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts the passed in ciphertext and returns the plaintext. Any
	// padding added to the plaintext during encryption is stripped.
	Decrypt(ciphertext []byte) (plaintext []byte, err error)

	// Marshaler marshals the cryptographic information in the cypher for
	// sending over the wire.
	json.Marshaler

	// Unmarshaler does not transfer the internal RNG. Use NewCipherFromJSON to
	// properly reconstruct a cipher from JSON.
	json.Unmarshaler
}

// cipher adheres to the Cipher interface.
type cipher struct {
	// secret is derived using deriveDatabaseSecret.
	secret []byte

	// blockSize is the maximum allowed length of the plaintext.
	//
	// Any plaintext that is shorter is padded to the length of blockSize so
	// that all encrypted data is of the same length. Any plaintext that is
	// longer is rejected.
	blockSize int

	// rng is the random number generator that is used to generate a nonce while
	// encrypting.
	rng io.Reader
}

// NewCipher generates a new Cipher from a password and salt.
//
// plaintextBlockSize is the maximum allowed length of any encrypted plaintext.
func NewCipher(internalPassword, salt []byte, plaintextBlockSize int,
	csprng io.Reader) (Cipher, error) {

	if plaintextBlockSize <= 0 {
		return nil, errors.Errorf(cipherInvalidBlockSizeErr, plaintextBlockSize)
	}

	// Generate key
	key := deriveDatabaseSecret(internalPassword, salt)

	return &cipher{
		secret:    key,
		blockSize: plaintextBlockSize,
		rng:       csprng,
	}, nil
}

// NewCipherFromJSON generates a new Cipher from its marshalled JSON and a
// CSPRNG.
func NewCipherFromJSON(data []byte, csprng io.Reader) (Cipher, error) {
	c := &cipher{rng: csprng}
	return c, json.Unmarshal(data, &c)
}

// Encrypt encrypts the raw data. The returned ciphertext includes the nonce
// (24 bytes) and the encrypted plaintext (with possible padding, if
// needed).
//
// Prior to encrypting the plaintext, a padding will be appended if it is
// shorter than the pre-defined block size passed into NewCipher.
//
// If the plaintext is longer than the block size, then Encrypt will return
// an error.
func (c *cipher) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if len(plaintext) > c.blockSize {
		return nil,
			errors.Errorf(plaintextTooLargeErr, c.blockSize, len(plaintext))
	}

	plaintext, err = appendPadding(plaintext, c.blockSize, c.rng)
	if err != nil {
		return nil, err
	}

	// Generate cipher and nonce
	chaCipher := initChaCha20Poly1305(c.secret)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err = io.ReadFull(c.rng, nonce); err != nil {
		jww.FATAL.Panicf(generateNoncePanic, err)
	}

	// Encrypt data and return
	ciphertext = chaCipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the passed in ciphertext and returns the plaintext. Any
// padding added to the plaintext during encryption is stripped.
func (c *cipher) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	// Generate cypher
	chaCipher := initChaCha20Poly1305(c.secret)

	nonceLen := chaCipher.NonceSize()
	if len(ciphertext)-nonceLen <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(ciphertext))
	}

	// The first nonceLen bytes of ciphertext are the nonce
	nonce, encrypted := ciphertext[:nonceLen], ciphertext[nonceLen:]

	// Decrypt ciphertext
	paddedPlaintext, err := chaCipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, errors.Errorf(cipherCannotDecryptErr, err)
	}

	// Remove padding from plaintext
	plaintext = discardPadding(paddedPlaintext)
	return plaintext, nil
}

// cipherDisk represents a cipher for marshalling and unmarshalling.
type cipherDisk struct {
	Secret    []byte `json:"secret"`
	BlockSize int    `json:"blockSize"`
}

// MarshalJSON marshals the cipher into valid JSON. This function adheres to the
// json.Marshaler interface.
func (c *cipher) MarshalJSON() ([]byte, error) {
	disk := cipherDisk{
		Secret:    c.secret,
		BlockSize: c.blockSize,
	}
	return json.Marshal(disk)
}

// UnmarshalJSON unmarshalls JSON into the cipher. This function adheres to the
// json.Unmarshaler interface.
//
// Note that this function does not transfer the internal RNG. Use
// NewCipherFromJSON to properly reconstruct a cipher from JSON.
func (c *cipher) UnmarshalJSON(data []byte) error {
	var disk cipherDisk
	err := json.Unmarshal(data, &disk)
	if err != nil {
		return err
	}

	c.secret = disk.Secret
	c.blockSize = disk.BlockSize

	return nil
}

// appendPadding adds padding to the end of a raw plaintext to make it the same
// length as the blockSize.
//
// If padding is added, it will result in a plaintext of the following form:
//
//	+-----------+-----------+---------+
//	| plaintext |    raw    | padding |
//	|   size    | plaintext |         |
//	+-----------+-----------+---------+
func appendPadding(plaintext []byte, blockSize int, rng io.Reader) ([]byte, error) {
	// Initialize result
	res := make([]byte, blockSize+lengthOfOverhead)

	// Serialize length of plaintext
	plaintextSize := len(plaintext)
	binary.PutUvarint(res, uint64(plaintextSize))

	// Put plaintext in result
	copy(res[lengthOfOverhead:], plaintext)

	// Add padding to the result from where plaintext ends
	padStart := lengthOfOverhead + plaintextSize
	n, err := rng.Read(res[padStart:])
	if err != nil {
		return nil, err
	}

	// Check that the correct amount of padding was read into the result
	padSize := blockSize - plaintextSize
	if n != padSize {
		return nil, errors.Errorf(shortPaddingReadErr, n, padSize)
	}

	return res, nil
}

// discardPadding strips the padding and data size from the plaintext.
func discardPadding(data []byte) []byte {
	plaintextSizeBytes := data[:lengthOfOverhead]
	plaintextSize, _ := binary.Uvarint(plaintextSizeBytes)
	return data[lengthOfOverhead : lengthOfOverhead+plaintextSize]
}

// deriveDatabaseSecret generates the key used for the encryption/decryption of
// channel message contents.
func deriveDatabaseSecret(password, salt []byte) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to generate cMix hash: %+v", err)
	}
	h.Write(password)
	h.Write(salt)
	return h.Sum(nil)
}
