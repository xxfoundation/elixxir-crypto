package broadcast

import (
	"crypto/sha256"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/multicastRSA"
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
