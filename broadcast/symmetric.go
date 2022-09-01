////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/e2e/auth"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/chacha20"
)

// Error messages.
const (
	// Symmetric.Decrypt
	errVerifyMAC = "failed to verify MAC"

	// NewSymmetricKey
	errMakeSymmetricKeyHash = "[BCAST] Failed to create new hash for " +
		"symmetric broadcast channel key: %+v"
)

const symmetricKeyConst = "symmetricBroadcastChannelKey"

func (c *Channel) EncryptSymmetric(payload []byte, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint) {
	nonce = newNonce(csprng)
	if c.key == nil {
		c.key = NewSymmetricKey(c.ReceptionID)
	}

	key := newMessageKey(nonce, c.key)
	encryptedPayload = auth.Crypt(key, nonce[:chacha20.NonceSizeX], payload)
	mac = makeMAC(key, encryptedPayload)

	return encryptedPayload, mac, nonce
}

func (c *Channel) DecryptSymmetric(encryptedPayload, mac []byte, nonce format.Fingerprint) ([]byte, error) {
	if c.key == nil {
		c.key = NewSymmetricKey(c.ReceptionID)
	}

	key := newMessageKey(nonce, c.key)
	payload := auth.Crypt(key, nonce[:chacha20.NonceSizeX], encryptedPayload)

	if !verifyMAC(key, encryptedPayload, mac) {
		return nil, errors.New(errVerifyMAC)
	}

	return payload, nil
}

// NewSymmetricKey generates a new symmetric channel key from its reception ID.
func NewSymmetricKey(receptionID *id.ID) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(errMakeSymmetricKeyHash, err)
	}

	h.Write(receptionID.Bytes())
	h.Write([]byte(symmetricKeyConst))

	return h.Sum(nil)
}
