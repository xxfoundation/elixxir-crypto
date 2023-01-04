////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

// Direct Messages are encrypted using the noise protocol X pattern. On the
// wire, the packet is readable by the destination using the ephemeral key
// against the recipients static public key, hiding the sender identity so long
// as the recipient's private key remains secret.
//
// The decrypted payload includes the senders static public key and a
// 16 byte benger code, which is a hash of the plaintext along with
// the key derived from both parties static keys. This prevents users
// from sending messages with identities they do not own, although they can
// still send (spoof) messages as each other.

import (
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
)

const (
	bengerCodeSize = 16
	prologueSize   = 2
)

var (
	Cipher DMCipher = &dmCipher{}
)

// DMCipher is a minimal abstraction for building the DMCipher Protocol layer
type DMCipher interface {
	// CiphertextOverhead returns the ciphertext overhead in bytes.
	CiphertextOverhead() int

	// Encrypt encrypts the given plaintext as an encrypted Direct message.
	Encrypt(plaintext []byte,
		senderStaticPrivKey nike.PrivateKey,
		partnerStaticPubKey nike.PublicKey,
		rng io.Reader,
		maxPayloadSize int) (ciphertext []byte)

	// Decrypt decrypts the given ciphertext encrypted as a Direct
	// message.
	Decrypt(ciphertext []byte, senderStaticPrivKey nike.PrivateKey) (
		partnerStaticPublicKey nike.PublicKey, plaintext []byte,
		err error)

	// IsSelfEncrypted will return whether the ciphertext provided has been
	// encrypted by the owner of the passed in private key. Returns true
	// if the ciphertext has been encrypted by the user.
	IsSelfEncrypted(data []byte, myPrivateKey nike.PrivateKey) bool

	// EncryptSelf will encrypt the passed plaintext. This will simulate the
	// encryption protocol in Encrypt, using just the user's public key.
	EncryptSelf(plaintext []byte, myPrivateKey nike.PrivateKey,
		partnerStaticPubKey nike.PublicKey,
		maxPayloadSize int) ([]byte, error)

	// DecryptSelf will decrypt the passed ciphertext. This will
	// check if the ciphertext is expected using IsSelfEncrypted.
	DecryptSelf(ciphertext []byte, myPrivateKey nike.PrivateKey) (
		partnerstaticPubKey nike.PublicKey, plaintext []byte, err error)
}

type dmCipher struct{}

func (s *dmCipher) CiphertextOverhead() int {
	return (NoiseX.CiphertextOverhead() + ecdh.ECDHNIKE.PublicKeySize() +
		bengerCodeSize + prologueSize)
}

// Encrypt encrypts the given plaintext as an encrypted Direct message.
// Direct Messages are Noise X messages with a payload that includes
// a keyed MAC based on the sender/partner static key derivation.
func (s *dmCipher) Encrypt(plaintext []byte,
	senderStaticPrivKey nike.PrivateKey,
	partnerStaticPubKey nike.PublicKey,
	rng io.Reader,
	maxCiphertextSize int) (ciphertext []byte) {

	if len(plaintext)+s.CiphertextOverhead() > maxCiphertextSize {
		jww.FATAL.Panicf("plaintext too large")
	}

	k := senderStaticPrivKey.DeriveSecret(partnerStaticPubKey)
	bengerCode := makeBengerCode(k, plaintext)
	senderPubKey := ecdh.ECDHNIKE.DerivePublicKey(senderStaticPrivKey)
	senderPubKeyBytes := senderPubKey.Bytes()

	payloadSize := maxCiphertextSize - NoiseX.CiphertextOverhead()

	// Format: PubKey | bengerCode | len(msg) | msg
	msg := make([]byte, payloadSize)
	copy(msg, senderPubKeyBytes)
	offset := len(senderPubKeyBytes)
	copy(msg[offset:], bengerCode)
	offset += len(bengerCode)
	binary.BigEndian.PutUint16(msg[offset:offset+prologueSize],
		uint16(len(plaintext)))
	offset += prologueSize
	copy(msg[offset:offset+len(plaintext)], plaintext)

	return NoiseX.Encrypt(msg, partnerStaticPubKey, rng)
}

// Decrypt decrypts the given ciphertext encrypted as a Direct
// message. This returns the partnerStaticPublicKey and the
// plaintext of the message.
func (s *dmCipher) Decrypt(ciphertext []byte,
	receiverStaticPrivKey nike.PrivateKey) (
	partnerStaticPublicKey nike.PublicKey, plaintext []byte,
	err error) {
	msg, err := NoiseX.Decrypt(ciphertext, receiverStaticPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// Format: PubKey | bengerCode | msg
	pubKey := ecdh.ECDHNIKE.NewEmptyPublicKey()
	pubSize := ecdh.ECDHNIKE.PublicKeySize()
	err = pubKey.FromBytes(msg[:pubSize])
	if err != nil {
		return nil, nil, err
	}

	offset := pubSize
	readBengerCode := msg[offset : offset+bengerCodeSize]
	offset += bengerCodeSize

	readMsgSize := binary.BigEndian.Uint16(
		msg[offset : offset+prologueSize])
	offset += prologueSize

	plaintext = msg[offset : offset+int(readMsgSize)]

	k := receiverStaticPrivKey.DeriveSecret(pubKey)

	if !isValidBengerCode(readBengerCode, k, plaintext) {
		return nil, nil, errors.Errorf("[DM] failed benger mac check")
	}

	return pubKey, plaintext, nil
}
