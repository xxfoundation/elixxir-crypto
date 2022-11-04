////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// IsSelfEncrypted will return whether the ciphertext provided has been
// encrypted by the owner of the passed in private key. Returns true
// if the ciphertext has been encrypted by the user.
func (s *scheme) IsSelfEncrypted(data []byte,
	myPrivateKey nike.PrivateKey) bool {

	// Pull nonce from ciphertext
	nonce := data[lengthOfOverhead:nonceSize]

	// Pull public key from ciphertext
	offset := lengthOfOverhead + nonceSize
	receivedPubKey := data[offset : offset+pubKeySize]

	// Construct expected public key using nonce in ciphertext and
	// the user's private key
	toHash := constructSelfCryptPublicKey(myPrivateKey.Bytes(), nonce)
	expectedPubKey := blake2b.Sum256(toHash[:])

	// Check that generated public key matches public key within ciphertext
	if hmac.Equal(receivedPubKey, expectedPubKey[:]) {
		return true
	}

	return false
}

// EncryptSelf will encrypt the passed plaintext. This will simulate the
// encryption protocol in Encrypt, using just the user's public key.
func (s *scheme) EncryptSelf(plaintext []byte, myPrivateKey nike.PrivateKey,
	maxPayloadSize int) ([]byte, error) {

	// Construct nonce
	nonce := make([]byte, nonceSize)
	count, err := csprng.NewSystemRNG().Read(nonce)
	if err != nil {
		return nil, err
	}
	if count != nonceSize {
		jww.FATAL.Panic("rng failure")
	}

	// Construct public key
	pubKey := constructSelfCryptPublicKey(myPrivateKey.Bytes(), nonce)

	// Construct key for ChaCha cipher
	chaKey := constructSelfChaKey(myPrivateKey.Bytes(), pubKey[:], nonce)

	// Construct cipher
	chaCipher, err := chacha20poly1305.NewX(chaKey[:])
	if err != nil {
		panic(fmt.Sprintf("Could not init XChaCha20Poly1305 mode: %s",
			err.Error()))
	}

	// Encrypt plaintext
	encrypted := chaCipher.Seal(nonce, nonce, plaintext, nil)
	res := make([]byte, maxPayloadSize)

	// Place the size of the payload (byte-serialized) at the beginning of the
	// ciphertext
	payloadSize := len(encrypted) + nonceSize + len(pubKey)
	binary.PutUvarint(res, uint64(payloadSize))

	// Place the nonce into the ciphertext
	copy(res[lengthOfOverhead:], nonce)

	// Place the public key into the ciphertext
	offset := lengthOfOverhead + nonceSize
	copy(res[offset:], pubKey[:])

	// Place the encrypted data into the ciphertext
	offset = offset + len(pubKey)
	copy(res[offset:], encrypted)

	// Fill the rest of the ciphertext with padding. This simulates the Noise
	// protocol.
	count, err = csprng.NewSystemRNG().Read(res[payloadSize+lengthOfOverhead:])
	if err != nil {
		jww.FATAL.Panic(err)
	}

	if count != maxPayloadSize-(payloadSize+lengthOfOverhead) {
		jww.FATAL.Panic("rng failure")
	}

	return res, nil
}

// DecryptSelf will decrypt the passed ciphertext. This will check if the
// ciphertext is expected using IsSelfEncrypted.
func (s *scheme) DecryptSelf(ciphertext []byte,
	myPrivateKey nike.PrivateKey) ([]byte, error) {
	if !s.IsSelfEncrypted(ciphertext, myPrivateKey) {
		return nil, errors.New("Could not confirm that data is self-encrypted")
	}

	// Pull nonce from ciphertext
	nonce := ciphertext[lengthOfOverhead:nonceSize]

	// Pull public key from ciphertext
	offset := lengthOfOverhead + nonceSize
	receivedPubKey := ciphertext[offset : offset+pubKeySize]

	// Find size of payload
	encryptedSizeBytes := ciphertext[:lengthOfOverhead]
	encryptedSize, _ := binary.Uvarint(encryptedSizeBytes)

	// Pull encrypted payload from ciphertext
	offset = offset + pubKeySize
	encrypted := ciphertext[offset:encryptedSize]

	// Construct key for decryption
	chaKey := constructSelfChaKey(myPrivateKey.Bytes(), receivedPubKey, nonce)

	// Construct cipher
	chaCipher, err := chacha20poly1305.NewX(chaKey[:])
	if err != nil {
		panic(fmt.Sprintf("Could not init XChaCha20Poly1305 mode: %s",
			err.Error()))
	}

	// Decrypt ciphertext
	plaintext, err := chaCipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// constructSelfChaKey is a helper function which generates the key
// used for self encryption and decryption.
func constructSelfChaKey(myPrivateKey, pubKey, nonce []byte) []byte {
	chaKey := make([]byte, 0)
	chaKey = append(chaKey, pubKey[:]...)
	chaKey = append(chaKey, nonce...)
	chaKey = append(chaKey, myPrivateKey...)
	return chaKey
}

// constructSelfCryptPublicKey is a helper function which will construct the
// facsimile "public key" will will be used to generate the key for self
// encryption.
func constructSelfCryptPublicKey(myPrivateKey, nonce []byte) [pubKeySize]byte {
	// Construct "public key"
	toHash := append(myPrivateKey, nonce...)
	return blake2b.Sum256(toHash)

}
