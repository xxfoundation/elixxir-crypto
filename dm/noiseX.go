////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"io"

	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/yawning/nyquist.git"
)

const (
	ciphertextOverhead = 96
)

var (
	NoiseX   NoiseCipher = &noiseX{}
	protocol *nyquist.Protocol
	version  = []byte{0x0, 0x0}
)

// NoiseCipher is a minimal abstraction useful for building a noise
// protocol layer.
type NoiseCipher interface {
	// CiphertextOverhead returns the ciphertext overhead in bytes.
	CiphertextOverhead() int

	// Encrypt encrypts the given plaintext as a Noise X message.
	// - plaintext: The message to Encrypt
	// - partnerStaticPubKey: The public key of the target of the message
	// - rng: a cryptographically secure pseudo random number generator
	Encrypt(plaintext []byte,
		partnerStaticPubKey nike.PublicKey,
		rng io.Reader) []byte

	// Decrypt decrypts the given ciphertext as a Noise X message.
	Decrypt(ciphertext []byte,
		myStatic nike.PrivateKey) ([]byte, error)
}

// noiseX is an implementation of NoiseScheme interface.
type noiseX struct{}

func (s *noiseX) CiphertextOverhead() int {
	// Noise overhead + prepended ephemeral public key
	return ciphertextOverhead + ecdh.ECDHNIKE.PublicKeySize()
}

// Encrypt encrypts the given plaintext as a Noise X message. The
// plaintext is encrypted using a key derived from an ephemerally
// generated private key (ecdhPrivate) and the static public key of
// the user (partnerStaticPubKey). A cryptographically secure random
// number generator is required to creat this key.
func (s *noiseX) Encrypt(plaintext []byte, partnerStaticPubKey nike.PublicKey,
	rng io.Reader) []byte {
	// Per spec, the X pattern in Noise relies on an ephemeral key. We
	// generate that here and prepend the public form to the message.
	ecdhPrivate, ecdhPublic := ecdh.ECDHNIKE.NewKeypair(rng)

	privKey := privateToNyquist(ecdhPrivate)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  true,
	}
	hs, err := nyquist.NewHandshake(cfg)
	panicOnError(err)
	defer hs.Reset()
	ciphertext, err := hs.WriteMessage(nil, plaintext)
	panicOnNoiseError(hs, err)
	return createNoisePayload(ciphertext, ecdhPublic)
}

// Decrypt decrypts the given ciphertext as a Noise X message.
func (s *noiseX) Decrypt(ciphertext []byte, myStatic nike.PrivateKey) (
	[]byte, error) {

	encrypted, partnerEphemeralPubKey, err := parseNoisePayload(ciphertext)
	if err != nil {
		return nil, err
	}

	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerEphemeralPubKey)

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

	plaintext, err := hs.ReadMessage(nil, encrypted)
	err = recoverErrorOnNoise(hs, err)

	return plaintext, err
}

// parseNoisePayload is a helper function which parses the
// ciphertext. This should be the inverse of createNoisePayload,
// returning to the user the encrypted data and the parsed public key.
func parseNoisePayload(payload []byte) ([]byte, nike.PublicKey, error) {
	// Extract the public key from the payload
	publicKeySize := ecdh.ECDHNIKE.PublicKeySize()
	publicKeyBytes := payload[:publicKeySize]
	publicKey, err := ecdh.ECDHNIKE.
		UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	// Extract encrypted data from payload
	ciphertext := payload[publicKeySize:]

	return ciphertext, publicKey, nil
}

// createNoisePayload is a helper function which will take the ciphertext
// and format it to fit Noise's specifications. The returned byte data should
// be formatted as such:
// Public Key | Ciphertext
func createNoisePayload(ciphertext []byte, ecdhPublic nike.PublicKey) []byte {
	publicKeySize := len(ecdhPublic.Bytes())
	ciphertextSize := len(ciphertext)
	res := make([]byte, publicKeySize+ciphertextSize)

	copy(res[0:publicKeySize], ecdhPublic.Bytes())
	copy(res[publicKeySize:], ciphertext)
	return res
}

func init() {
	var err error
	protocol, err = nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	panicOnError(err)
}
