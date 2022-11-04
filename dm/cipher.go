////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"encoding/binary"
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/yawning/nyquist.git"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	prologueSize       = 2
	ciphertextOverhead = 96

	// lengthOfOverhead is the reserved bytes used to indicate the serialized
	// length of the payload within a ciphertext.
	lengthOfOverhead = 2

	// pubKeySize is the size of the facsimile public key used for self
	// encryption/decryption.
	pubKeySize = blake2b.Size256

	// nonceSize is the size of the nonce used for the encryption
	// algorithm used for self encryption/decryption.
	nonceSize = chacha20poly1305.NonceSize
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
		partnerStaticPubKey nike.PublicKey,
		maxPayloadSize int) []byte

	// Decrypt decrypts the given ciphertext as a Noise X message.
	Decrypt(ciphertext []byte,
		myStatic nike.PrivateKey) ([]byte, error)

	// IsSelfEncrypted will return whether the ciphertext provided has been
	// encrypted by the owner of the passed in private key. Returns true
	// if the ciphertext has been encrypted by the user.
	IsSelfEncrypted(data []byte, myPrivateKey nike.PrivateKey) bool

	// EncryptSelf will encrypt the passed plaintext. This will simulate the
	// encryption protocol in Encrypt, using just the user's public key.
	EncryptSelf(plaintext []byte, myPrivateKey nike.PrivateKey,
		maxPayloadSize int) ([]byte, error)

	// DecryptSelf will decrypt the passed ciphertext. This will check if the
	// ciphertext is expected using IsSelfEncrypted.
	DecryptSelf(ciphertext []byte, myPrivateKey nike.PrivateKey) ([]byte, error)
}

// scheme is an implementation of NoiseScheme interface.
type scheme struct{}

var _ NoiseScheme = (*scheme)(nil)

func (s *scheme) CiphertextOverhead() int {
	return ciphertextOverhead
}

// Encrypt encrypts the given plaintext as a Noise X message.
func (s *scheme) Encrypt(plaintext []byte, partnerStaticPubKey nike.PublicKey,
	maxPayloadSize int) []byte {
	ecdhPrivate, ecdhPublic := ecdh.ECDHNIKE.NewKeypair()

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
	fmt.Printf("ciphertext: %v\n", ciphertext)
	return ciphertextToNoise(ciphertext, ecdhPublic, maxPayloadSize)
}

// Decrypt decrypts the given ciphertext as a Noise X message.
func (s *scheme) Decrypt(ciphertext []byte, myStatic nike.PrivateKey) ([]byte, error) {

	encrypted, partnerStaticPubKey, err := parseCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}

	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  false,
	}

	fmt.Printf("ciphertext: %v\n", encrypted)

	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		return nil, err
	}
	defer hs.Reset()

	plaintext, err := hs.ReadMessage(nil, encrypted)
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

// parseCiphertext is a helper function which parses the ciphertext. This should
// be the inverse of ciphertextToNoise, returning to the user
// the encrypted data and the public key.
func parseCiphertext(ciphertext []byte) ([]byte, nike.PublicKey, error) {
	// Extract the payload from the ciphertext
	lengthOfPayloadBytes := ciphertext[:lengthOfOverhead]
	payloadSize, _ := binary.Uvarint(lengthOfPayloadBytes)
	payload := ciphertext[lengthOfOverhead:payloadSize]

	// Extract the public key from the payload
	publicKeySize := ecdh.ECDHNIKE.PublicKeySize()
	publicKeyBytes := payload[:publicKeySize]
	publicKey, err := ecdh.ECDHNIKE.
		UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	// Extract encrypted data from payload
	encrypted := payload[publicKeySize:]

	return encrypted, publicKey, nil
}

// ciphertextToNoise is a helper function which will take the ciphertext
// and format it to fit Noise's specifications. The returned byte data should
// be formatted as such:
// Length of Payload | Public Key | Ciphertext | Random Data
func ciphertextToNoise(ciphertext []byte,
	ecdhPublic nike.PublicKey, maxPayloadSize int) []byte {
	res := make([]byte, maxPayloadSize)

	lengthOfPublicKey := len(ecdhPublic.Bytes())
	actualPayloadSize := lengthOfPublicKey + len(ciphertext) + lengthOfOverhead

	// Put at the start the length of the payload (ciphertext)
	binary.PutUvarint(res, uint64(actualPayloadSize))

	// Put in the public key per the Noise spec
	copy(res[lengthOfOverhead:], ecdhPublic.Bytes())

	// Put in the cipher text
	copy(res[lengthOfOverhead+lengthOfPublicKey:], ciphertext)

	// Fill the rest of the context with random data
	rng := csprng.NewSystemRNG()
	count, err := rng.Read(res[actualPayloadSize:])
	if err != nil {
		jww.FATAL.Panic(err)
	}

	if count != maxPayloadSize-(actualPayloadSize) {
		jww.FATAL.Panic("rng failure")
	}

	return res
}

func init() {
	var err error
	protocol, err = nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		jww.FATAL.Panic(err)
	}
}
