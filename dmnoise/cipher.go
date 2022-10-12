package dmnoise

import (
	"gitlab.com/yawning/nyquist.git"
	"gitlab.com/yawning/nyquist.git/dh"
)

func Encrypt(plaintext []byte, myStatic dh.Keypair, partnerStaticPubKey dh.PublicKey) []byte {
	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		panic(err)
	}
	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  myStatic,
		RemoteStatic: partnerStaticPubKey,
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

func Decrypt(ciphertext []byte, myStatic dh.Keypair, partnerStaticPubKey dh.PublicKey) ([]byte, error) {
	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		return nil, err
	}
	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		LocalStatic:  myStatic,
		RemoteStatic: partnerStaticPubKey,
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
