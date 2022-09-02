package broadcast

import (
	"hash"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
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

	// NewSymmetricKey
	errMakeSymmetricKeyHash = "[BCAST] Failed to create new hash for " +
		"symmetric broadcast channel key: %+v"
)

const symmetricKeyConst = "symmetricBroadcastChannelKey"

func (c *Channel) EncryptSymmetric(payload []byte, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint) {
	nonce = newNonce(csprng)
	var err error
	if c.key == nil {
		c.key, err = NewSymmetricKey(c.Name, c.Description, c.Salt, c.RsaPubKey.GetN().Bytes(), c.Secret)
		if err != nil {
			panic(err)
		}
	}

	key := newMessageKey(nonce, c.key)
	encryptedPayload = auth.Crypt(key, nonce[:chacha20.NonceSizeX], payload)
	mac = makeMAC(key, encryptedPayload)

	return encryptedPayload, mac, nonce
}

func (c *Channel) DecryptSymmetric(encryptedPayload, mac []byte, nonce format.Fingerprint) ([]byte, error) {
	var err error
	if c.key == nil {
		c.key, err = NewSymmetricKey(c.Name, c.Description, c.Salt, c.RsaPubKey.GetN().Bytes(), c.Secret)
		if err != nil {
			panic(err)
		}
	}

	key := newMessageKey(nonce, c.key)
	payload := auth.Crypt(key, nonce[:chacha20.NonceSizeX], encryptedPayload)

	if !verifyMAC(key, encryptedPayload, mac) {
		return nil, errors.New(errVerifyMAC)
	}

	return payload, nil
}

// NewSymmetricKey generates a new symmetric channel key.
func NewSymmetricKey(name, description string, salt, rsaPub, secret []byte) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("NewChannelID secret must be 32 bytes long.")
	}

	hkdfHash := func() hash.Hash {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	}

	hkdf := hkdf.New(hkdfHash,
		secret,
		deriveIntermediary(name, description, salt, rsaPub, secret),
		[]byte(hkdfInfo))

	key := make([]byte, 32)
	n, err := io.ReadFull(hkdf, key)
	if err != nil {
		panic(err)
	}
	if n != 32 {
		panic("failed to read from hkdf")
	}

	return key, nil
}
