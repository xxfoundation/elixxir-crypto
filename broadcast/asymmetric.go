package broadcast

import (
	"crypto/sha256"
	"github.com/pkg/errors"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/crypto/signature/rsa"

	"gitlab.com/elixxir/primitives/format"
)

func (c *Channel) EncryptAsymmetric(payload []byte, pk multicastRSA.PrivateKey, pubKey *rsa.PublicKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	innerCiphertext, err := multicastRSA.EncryptOAEP(sha256.New(), csprng, pk, payload, c.label())
	if err != nil {
		return nil, nil, format.Fingerprint{}, errors.WithMessage(err, "Failed to encrypt asymmetric broadcast message")
	}

	innerPayload := append(pubKey.Bytes(), innerCiphertext...)
	encryptedPayload, mac, nonce = c.EncryptSymmetric(innerPayload, csprng)

	return
}

func (c *Channel) DecryptAsymmetric(payload []byte, mac []byte, nonce format.Fingerprint) ([]byte, error) {
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
