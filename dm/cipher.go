////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/yawning/nyquist.git"
)

const (
	prologueSize       = 2
	ciphertextOverhead = 96
)

var (
	Cipher   NoiseScheme = &scheme{}
	protocol *nyquist.Protocol
	version  = []byte{0x0, 0x0}
)

// NoiseScheme is a minimal abstraction useful for building a noise
// protocol layer.
type NoiseScheme interface {
	// CiphertextOverhead returns the ciphertext overhead in bytes.
	CiphertextOverhead() int

	// Encrypt encrypts the given plaintext as a Noise X message.
	Encrypt(plaintext []byte,
		myStatic nike.PrivateKey,
		partnerStaticPubKey nike.PublicKey) []byte

	// Decrypt decrypts the given ciphertext as a Noise X message.
	Decrypt(ciphertext []byte,
		myStatic nike.PrivateKey,
		partnerStaticPubKey nike.PublicKey) ([]byte, error)
}

// scheme is an implementation of NoiseScheme interface.
type scheme struct{}

var _ NoiseScheme = (*scheme)(nil)

func (s *scheme) CiphertextOverhead() int {
	return ciphertextOverhead
}

func (s *scheme) Encrypt(plaintext []byte, myStatic nike.PrivateKey, partnerStaticPubKey nike.PublicKey) []byte {
	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  true,
	}
	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	defer hs.Reset()
	ciphertext, err := hs.WriteMessage(nil, plaintext)
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			jww.FATAL.Panic(status.Err)
		}
	case nil:
	default:
		jww.FATAL.Panic(err)
	}
	return ciphertext
}

func (s *scheme) Decrypt(ciphertext []byte, myStatic nike.PrivateKey, partnerStaticPubKey nike.PublicKey) ([]byte, error) {

	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	protocol, err := nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		return nil, err
	}
	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
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

func init() {
	var err error
	protocol, err = nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		jww.FATAL.Panic(err)
	}
}
