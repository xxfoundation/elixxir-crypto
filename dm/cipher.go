package dm

import (
	"gitlab.com/yawning/nyquist.git"
)

const ciphertextOverhead = 96

var Cipher NoiseScheme = &scheme{}

type NoiseScheme interface {
	// CiphertextOverhead returns the ciphertext overhead in bytes.
	CiphertextOverhead() int

	// Encrypt encrypts the given plaintext as a Noise X message.
	Encrypt(plaintext []byte,
		myStatic *PrivateKey,
		partnerStaticPubKey *PublicKey) []byte

	// Decrypt decrypts the given ciphertext as a Noise X message.
	Decrypt(ciphertext []byte,
		myStatic *PrivateKey,
		partnerStaticPubKey *PublicKey) ([]byte, error)
}

type scheme struct{}

func (s *scheme) CiphertextOverhead() int {
	return ciphertextOverhead
}

func (s *scheme) Encrypt(plaintext []byte, myStatic *PrivateKey, partnerStaticPubKey *PublicKey) []byte {
	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		panic(err)
	}
	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  myStatic.privateKey,
		RemoteStatic: partnerStaticPubKey.publicKey,
		IsInitiator:  true,
	}
	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		panic(err)
	}
	defer hs.Reset()
	ciphertext, err := hs.WriteMessage(nil, plaintext)
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			panic(status.Err)
		}
	case nil:
	default:
		panic(err)
	}
	return ciphertext
}

func (s *scheme) Decrypt(ciphertext []byte, myStatic *PrivateKey, partnerStaticPubKey *PublicKey) ([]byte, error) {
	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		return nil, err
	}
	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  myStatic.privateKey,
		RemoteStatic: partnerStaticPubKey.publicKey,
		IsInitiator:  false,
	}

	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		return nil, err
	}
	defer hs.Reset()

	plaintext, err := hs.ReadMessage(nil, ciphertext)
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			return nil, status.Err
		}
	case nil:
	default:
		return nil, err
	}
	return plaintext, nil
}
