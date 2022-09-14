package broadcast

import (
	"crypto/rsa"
	"crypto/sha256"

	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"

	"gitlab.com/elixxir/primitives/format"
)

func (c *Channel) EncryptAsymmetric(payload []byte, pk multicastRSA.PrivateKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {
	h := sha256.New()
	// Note: this doesn't really do much
	nonce = newNonce(csprng)
	key := newMessageKey(nonce, pk.GetN().Bytes())
	mac = makeMAC(key, payload)

	// Encrypt payload using multicastRSA
	encryptedPayload, err = multicastRSA.EncryptOAEP(h, csprng, pk, payload, c.label())
	if err != nil {
		return nil, nil, format.Fingerprint{}, errors.WithMessage(err, "Failed to encrypt asymmetric broadcast message")
	}

	return
}

func (c *Channel) DecryptAsymmetric(payload []byte) ([]byte, error) {
	h := sha256.New()
	decrypted, err := multicastRSA.DecryptOAEP(h, c.RsaPubKey, payload, c.label())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (c *Channel) MaxAsymmetricPayloadSize() int {
	return multicastRSA.GetMaxPayloadSize(sha256.New(), c.RsaPubKey)
}

// EncryptRSAToPrivate encrypts the given plaintext with the given
// RSA public key.
func EncryptRSAToPrivate(plaintext []byte, rng csprng.Source, pub *rsa.PublicKey, label []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return rsa.EncryptOAEP(h, rng, pub, plaintext, label)
}

// DecryptRSAToPrivate decrypts the given ciphertext with the given RSA private key.
func DecryptRSAToPrivate(ciphertext []byte, rng csprng.Source, priv *rsa.PrivateKey, label []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return rsa.DecryptOAEP(h, rng, priv, ciphertext, label)
}
