package dm

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/yawning/nyquist.git"
)

const ciphertextOverhead = 96

var Cipher NoiseScheme = &scheme{}

var protocol *nyquist.Protocol

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

/*

// DH is a Diffie-Hellman key exchange algorithm.
type DH interface {
	fmt.Stringer

	// GenerateKeypair generates a new Diffie-Hellman keypair using the
	// provided entropy source.
	GenerateKeypair(rng io.Reader) (Keypair, error)

	// ParsePrivateKey parses a binary encoded private key.
	ParsePrivateKey(data []byte) (Keypair, error)

	// ParsePublicKey parses a binary encoded public key.
	ParsePublicKey(data []byte) (PublicKey, error)

	// Size returns the size of public keys and DH outputs in bytes (`DHLEN`).
	Size() int
}

*/

type scheme struct{}

func (s *scheme) CiphertextOverhead() int {
	return ciphertextOverhead
}

func (s *scheme) Encrypt(plaintext []byte, myStatic nike.PrivateKey, partnerStaticPubKey nike.PublicKey) []byte {
	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
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
