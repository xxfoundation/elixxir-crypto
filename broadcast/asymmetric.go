package broadcast

import (
	"bytes"
	"crypto/sha256"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/crypto/signature/rsa"

	"gitlab.com/elixxir/primitives/format"
)

func (c *Channel) IsPublicKeyHashMatch(publicKey *rsa.PublicKey) bool {
	if bytes.Equal(c.RsaPubKeyHash, hashSecret(publicKey.Bytes())) {
		return true
	}
	return false
}

func (c *Channel) EncryptRSAToPublic(payload []byte, privkey *rsa.PrivateKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	if !c.IsPublicKeyHashMatch(privkey.GetPublic()) {
		return nil, nil, nonce, errors.New("private key does not derive a public key whose hash matches our public key hash")
	}

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
func (c *Channel) EncryptRSAToPrivate(plaintext []byte, rng csprng.Source, privkey multicastRSA.PrivateKey) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return multicastRSA.EncryptOAEP(h, rng, privkey, plaintext, c.label())
}

// DecryptRSAToPrivate decrypts the given ciphertext with the given RSA private key.
func (c *Channel) DecryptRSAToPrivate(ciphertext []byte, rng csprng.Source, priv multicastRSA.PrivateKey) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	return multicastRSA.DecryptOAEP(h, priv, ciphertext, c.label())
}
