////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"

	"gitlab.com/elixxir/crypto/e2e/auth"
	"gitlab.com/elixxir/primitives/format"
)

// Error messages.
const (
	// Symmetric.Decrypt
	errVerifyMAC = "failed to verify MAC"
)

// ErrPayloadTooBig is returned if the payload is too large
var ErrPayloadTooBig = errors.New("cannot symmetrically encrypt the " +
	"payload, it is too large")

// GetMaxSymmetricPayloadSize returns the maximum size that a symmetric
// payload can be based upon the size of the packet it must fit in
func (c *Channel) GetMaxSymmetricPayloadSize(outerPayloadSize int) int {
	return MaxSizedBroadcastPayloadSize(outerPayloadSize)
}

// EncryptSymmetric symmetrically encrypts the payload with the key after padding
// The payload must not be longer than Channel.GetMaxSymmetricPayloadSize()
func (c *Channel) EncryptSymmetric(payload []byte, outerPayloadSize int,
	csprng csprng.Source) (encryptedPayload, mac []byte,
	nonce format.Fingerprint, err error) {

	// edge check
	if len(payload) > c.GetMaxSymmetricPayloadSize(outerPayloadSize) {
		return nil, nil, format.Fingerprint{}, ErrPayloadTooBig
	}

	// pad the payload up to the outer payload size, which should be the size
	// of the packet it needs to fit in
	// this has a minimum of 8 bytes of random padding as defence in depth
	sizedPayload, err := NewSizedBroadcast(outerPayloadSize, payload, csprng)
	if err != nil {
		jww.FATAL.Panicf("Failed to size the symmetric broadcast: %+v", err)
	}

	nonce = newNonce(csprng)
	key := newMessageKey(nonce, c.getSymmetricKey())
	encryptedPayload = auth.Crypt(key, nonce[:chacha20.NonceSizeX], sizedPayload)
	mac = makeMAC(key, encryptedPayload)

	return encryptedPayload, mac, nonce, nil
}

// DecryptSymmetric symmetrically decrypts the payload with the key after padding
func (c *Channel) DecryptSymmetric(encryptedPayload, mac []byte,
	nonce format.Fingerprint) ([]byte, error) {

	key := newMessageKey(nonce, c.getSymmetricKey())
	sizedPayload := auth.Crypt(key, nonce[:chacha20.NonceSizeX],
		encryptedPayload)

	if !verifyMAC(key, encryptedPayload, mac) {
		return nil, errors.New(errVerifyMAC)
	}

	payload, err := DecodeSizedBroadcast(sizedPayload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// getSymmetricKey lazy instantiates the symmetric key and returns it
func (c *Channel) getSymmetricKey() []byte {
	var err error
	if c.key == nil {
		c.key, err = NewSymmetricKey(c.Name, c.Description, c.Level, c.Created,
			c.Salt, c.RsaPubKeyHash, c.Secret)
		if err != nil {
			jww.FATAL.Panic(err)
		}
	}
	return c.key
}

// NewSymmetricKey generates a new symmetric channel key, which is derived like
// this:
//
//  intermediary = H(name | description | level | created | rsaPubHash | hashedSecret | salt)
//  key = HKDF(secret, intermediary, hkdfInfo)
func NewSymmetricKey(name, description string, level PrivacyLevel,
	creation time.Time, salt, rsaPubHash, secret []byte) ([]byte, error) {
	if len(secret) != 32 {
		jww.FATAL.Panic(fmt.Sprintf("secret len is %d", len(secret)))
		return nil, ErrSecretSizeIncorrect
	}

	hkdfHash := func() hash.Hash {
		h, err := channelHash(nil)
		if err != nil {
			jww.FATAL.Panic(err)
		}
		return h
	}

	hkdfReader := hkdf.New(hkdfHash, secret,
		deriveIntermediary(name, description, level, creation, salt, rsaPubHash,
			HashSecret(secret)), []byte(hkdfInfo))

	// 256 bits of entropy
	key := make([]byte, 32)
	n, err := io.ReadFull(hkdfReader, key)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != 32 {
		jww.FATAL.Panic("failed to read from hkdf")
	}

	return key, nil
}
