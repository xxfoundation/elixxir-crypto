////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	selfHMACSalt   = "sendSelfHMACSalt"
	selfSecretSalt = "sendSelfSecretKeySalt"
)

var (
	encryptedSelfOverhead = chacha20poly1305.Overhead +
		chacha20poly1305.NonceSizeX + hash.DefaultHash().Size()
	selfOverhead = (encryptedSelfOverhead + prologueSize +
		ecdh.ECDHNIKE.PublicKeySize())
)

// IsSelfEncrypted will return whether the ciphertext provided has been
// encrypted by the owner of the passed in private key. Returns true
// if the ciphertext has been encrypted by the user.
func (s *dmCipher) IsSelfEncrypted(data []byte,
	myPrivateKey nike.PrivateKey) bool {

	esdm, err := newEncryptedSelfDMFromBytes(data)
	if err != nil {
		jww.WARN.Printf("IsSelfEncrypted: malformed data")
		return false
	}
	key := deriveSelfSecretKey(esdm.nonce, myPrivateKey)
	return checkHMAC(esdm.mac, esdm.nonce, esdm.ciphertext, key)
}

// EncryptSelf will encrypt the passed plaintext. This will simulate the
// encryption protocol in Encrypt, using just the user's public key.
func (s *dmCipher) EncryptSelf(message []byte, myPrivateKey nike.PrivateKey,
	partnerPublicKey nike.PublicKey,
	maxPayloadSize int) ([]byte, error) {

	if len(message)+selfOverhead > maxPayloadSize {
		return nil, errors.Errorf("message too big: %d > %d",
			len(message)+selfOverhead, maxPayloadSize)
	}

	// sdm is the plaintext part of the packet, so it is the size
	// of the payload less encryption overhead
	sdm := newSelfDM(maxPayloadSize - encryptedSelfOverhead)
	sdm.setMsg(message)
	sdm.setPubKey(partnerPublicKey)

	// Construct nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	count, err := csprng.NewSystemRNG().Read(nonce)
	if err != nil {
		return nil, err
	}
	panicOnRngFailure(count, chacha20poly1305.NonceSizeX)

	key := deriveSelfSecretKey(nonce, myPrivateKey)

	chaCipher, err := chacha20poly1305.NewX(key)
	panicOnChaChaFailure(err)
	ciphertext := chaCipher.Seal(nil, nonce, sdm.plaintext, nil)

	esdm := newEncryptedSelfDM(maxPayloadSize)
	esdm.setNonce(nonce)
	esdm.setMAC(getSelfHMAC(key, ciphertext, nonce))
	esdm.setCiphertext(ciphertext)
	return esdm.payload, nil
}

// DecryptSelf will decrypt the passed ciphertext. This will check if the
// ciphertext is expected using IsSelfEncrypted.
func (s *dmCipher) DecryptSelf(ciphertext []byte,
	myPrivateKey nike.PrivateKey) (partnerStaticPubKey nike.PublicKey,
	plaintext []byte, err error) {

	esdm, err := newEncryptedSelfDMFromBytes(ciphertext)
	if err != nil {
		return nil, nil, errors.Errorf(
			"Could not confirm that data is self-encrypted: %+v",
			err)
	}
	key := deriveSelfSecretKey(esdm.nonce, myPrivateKey)

	if !checkHMAC(esdm.mac, esdm.nonce, esdm.ciphertext, key) {
		return nil, nil, errors.Errorf(
			"failed hmac")

	}

	chaCipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	msg, err := chaCipher.Open(nil, esdm.nonce, esdm.ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	sdm, err := newSelfDMFromBytes(msg)
	if err != nil {
		return nil, nil, err
	}

	partnerStaticPubKey, err = sdm.getPubKey()
	if err != nil {
		return nil, nil, err
	}
	plaintext, err = sdm.getMsg()
	if err != nil {
		return nil, nil, err
	}

	return partnerStaticPubKey, plaintext, nil
}

// deriveSelfSecretKey is a helper function which generates the key
// used for self encryption and decryption.
func deriveSelfSecretKey(nonce []byte, privateKey nike.PrivateKey) []byte {
	h := hash.DefaultHash()
	h.Write([]byte(selfSecretSalt))
	h.Write(nonce)
	h.Write(privateKey.Bytes())
	return h.Sum(nil)
}

func getSelfHMAC(key, msg, nonce []byte) []byte {
	// Construct an additional hmac used to check if it's a self-encrypted
	// msg (this is somewhat unnecessary due to poly1305, but we have the
	// space in the packet).
	mac := hmac.New(hash.DefaultHash, key)
	mac.Write([]byte(selfHMACSalt))
	mac.Write(nonce)
	mac.Write(msg)
	return mac.Sum(nil)
}

func checkHMAC(mac, nonce, ciphertext, key []byte) bool {
	receivedMAC := getSelfHMAC(key, ciphertext, nonce)
	return hmac.Equal(receivedMAC, mac)
}

type selfDM struct {
	plaintext []byte
	pubkey    []byte
	size      []byte
	msg       []byte
}

func (sd *selfDM) setPubKey(pubkey nike.PublicKey) {
	copy(sd.pubkey, pubkey.Bytes())
}
func (sd *selfDM) setMsg(msg []byte) {
	binary.BigEndian.PutUint16(sd.size, uint16(len(msg)))
	copy(sd.msg, msg)
}
func (sd *selfDM) getPubKey() (nike.PublicKey, error) {
	pubKey := ecdh.ECDHNIKE.NewEmptyPublicKey()
	err := pubKey.FromBytes(sd.pubkey)
	return pubKey, err
}
func (sd *selfDM) getMsg() ([]byte, error) {
	size := int(binary.BigEndian.Uint16(sd.size))
	if len(sd.msg) < size {
		return nil, errors.Errorf("invalid size: %d > %d",
			sd.size, len(sd.msg))
	}
	return sd.msg[:size], nil
}

func newSelfDM(size int) *selfDM {
	sd := &selfDM{
		plaintext: make([]byte, size),
	}
	start := 0
	end := ecdh.ECDHNIKE.PublicKeySize()
	sd.pubkey = sd.plaintext[start:end]
	start = end
	end = start + prologueSize
	sd.size = sd.plaintext[start:end]
	start = end
	end = size
	sd.msg = sd.plaintext[start:end]
	return sd
}

func newSelfDMFromBytes(b []byte) (*selfDM, error) {
	minSize := hash.DefaultHash().Size() + chacha20poly1305.NonceSizeX
	if len(b) < minSize {
		return nil, errors.Errorf("data too small for selfDM: %d < %d",
			len(b), minSize)
	}
	sd := newSelfDM(len(b))
	copy(sd.plaintext, b)
	return sd, nil
}

type encryptedSelfDM struct {
	payload    []byte
	mac        []byte
	nonce      []byte
	ciphertext []byte
}

func (sd *encryptedSelfDM) setMAC(mac []byte) {
	copy(sd.mac, mac)
}
func (sd *encryptedSelfDM) setNonce(nonce []byte) {
	copy(sd.nonce, nonce)
}
func (sd *encryptedSelfDM) setCiphertext(ciphertext []byte) {
	copy(sd.ciphertext, ciphertext)
}

func newEncryptedSelfDM(size int) *encryptedSelfDM {
	sd := &encryptedSelfDM{
		payload: make([]byte, size),
	}
	start := 0
	end := hash.DefaultHash().Size()
	sd.mac = sd.payload[start:end]
	start = end
	end = start + chacha20poly1305.NonceSizeX
	sd.nonce = sd.payload[start:end]
	start = end
	end = size
	sd.ciphertext = sd.payload[start:end]
	return sd
}

func newEncryptedSelfDMFromBytes(b []byte) (*encryptedSelfDM, error) {
	minSize := hash.DefaultHash().Size() + chacha20poly1305.NonceSizeX
	if len(b) < minSize {
		return nil, errors.Errorf(
			"data too small for encryptedSelfDM: %d < %d",
			len(b), minSize)
	}
	sd := newEncryptedSelfDM(len(b))
	copy(sd.payload, b)
	return sd, nil
}
