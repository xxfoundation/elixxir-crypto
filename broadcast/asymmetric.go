package broadcast

import (
	"crypto/sha256"

	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/crypto/signature/rsa"

	"gitlab.com/elixxir/primitives/format"
)

func (c *Channel) EncryptRSAToPublic(payload []byte, privkey *rsa.PrivateKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	innerCiphertext, err := multicastRSA.EncryptOAEP(sha256.New(), csprng, privkey, payload, c.label())
	if err != nil {
		return nil, nil, format.Fingerprint{}, errors.WithMessage(err, "Failed to encrypt asymmetric broadcast message")
	}

	innerPayload := append(privkey.GetPublic().Bytes(), innerCiphertext...)
	encryptedPayload, mac, nonce = c.EncryptSymmetric(innerPayload, csprng)

	return
}

func (c *Channel) DecryptRSAToPublic(payload []byte, mac []byte, nonce format.Fingerprint) ([]byte, error) {
	innerCiphertext, err := c.DecryptSymmetric(payload, mac, nonce)
	if err != nil {
		return nil, err
	}

	rsaPubKeyBytes := innerCiphertext[:c.RsaPubKeyLength]
	ciphertext := innerCiphertext[c.RsaPubKeyLength:]

	h := sha256.New()
	rsaPubKey := new(rsa.PublicKey)
	err = rsaPubKey.FromBytes(rsaPubKeyBytes)
	if err != nil {
		return nil, err
	}
	decrypted, err := multicastRSA.DecryptOAEP(h, rsaPubKey, ciphertext, c.label())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (c *Channel) MaxAsymmetricPayloadSize(pk multicastRSA.PublicKey) int {
	return multicastRSA.GetMaxPayloadSize(sha256.New(), pk)
}

// EncryptRSAToPrivate encrypts the given plaintext with the given
// RSA public key.
func EncryptRSAToPrivate(plaintext []byte, rng csprng.Source, privkey multicastRSA.PrivateKey, label []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return multicastRSA.EncryptOAEP(h, rng, privkey, plaintext, label)
}

// DecryptRSAToPrivate decrypts the given ciphertext with the given RSA private key.
func DecryptRSAToPrivate(ciphertext []byte, rng csprng.Source, priv multicastRSA.PrivateKey, label []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return multicastRSA.DecryptOAEP(h, priv, ciphertext, label)
}
