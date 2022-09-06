package broadcast

import (
	"crypto/sha256"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
	"gitlab.com/xx_network/crypto/signature/rsa"
)

func (c *Channel) EncryptAsymmetric(payload []byte, pk multicastRSA.PrivateKey, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	h := sha256.New()
	// Note: this doesn't really do much
	nonce = newNonce(csprng)
	key := newMessageKey(nonce, pk.GetN().Bytes())
	mac = makeMAC(key, payload)

	// Encrypt payload using multicastRSA
	innerCiphertext, err := multicastRSA.EncryptOAEP(h, csprng, pk, payload, c.label())
	if err != nil {
		return nil, nil, format.Fingerprint{}, errors.WithMessage(err, "Failed to encrypt asymmetric broadcast message")
	}

	innerPayload := append(rsa.CreatePublicKeyPem(pk), innerCiphertext...)
	encryptedPayload, mac, nonce = c.EncryptSymmetric(innerPayload, csprng)

	return
}

func (c *Channel) DecryptAsymmetric(payload []byte, mac []byte, nonce format.Fingerprint) ([]byte, error) {

	rsaPubKeyBytes := payload[:c.RsaPubKeyLength]
	outerCiphertext := payload[c.RsaPubKeyLength:]
	innerCiphertext, err := c.DecryptSymmetric(outerCiphertext, mac, nonce)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	rsaPubKey, err := rsa.LoadPublicKeyFromPem(rsaPubKeyBytes)
	if err != nil {
		return nil, err
	}
	decrypted, err := multicastRSA.DecryptOAEP(h, rsaPubKey, innerCiphertext, c.label())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (c *Channel) MaxAsymmetricPayloadSize(pk multicastRSA.PublicKey) int {
	return multicastRSA.GetMaxPayloadSize(sha256.New(), pk)
}
