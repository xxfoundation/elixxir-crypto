////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
)

// IsPublicKey returns true if the passed public key is the public key for the
// given channel
func (c *Channel) IsPublicKey(publicKey rsa.PublicKey) bool {
	if bytes.Equal(c.RsaPubKeyHash, HashPubKey(publicKey)) {
		return true
	}
	return false
}

// GetRSAToPublicMessageLength returns the size of the internal payload for
// RSAtoPublic encrypted messages. It returns the total size, the number of
// sub-payloads, and the size of each sub-payloads
func (c *Channel) GetRSAToPublicMessageLength() (size int, numSubPayloads int,
	subPayloadSize int) {
	// Get the number of bytes in each sub-payload
	h, _ := channelHash(nil)
	subPayloadSize = rsa.GetMaxOEAPPayloadSize(h, c.RsaPubKeyLength)
	numSubPayloads = c.RSASubPayloads
	size = subPayloadSize * numSubPayloads
	return
}

// EncryptRSAToPublic encrypts the payload with the private key. The payload
// must not be longer than Channel.GetRSAToPublicMessageLength().
//
//	symmetric{pubkey | (rsa{p[0]} | rsa{p[1]} | ... | rsa0{p[n]}) | padding}
func (c *Channel) EncryptRSAToPublic(payload []byte, privKey rsa.PrivateKey,
	outerPayloadSize int, csprng csprng.Source) (singleEncryptedPayload,
	doubleEncryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	// Check that they are using the proper key
	if !c.IsPublicKey(privKey.Public()) {
		return nil, nil, nil, nonce, errors.New("private key does not derive " +
			"a public key whose hash matches our public key hash")
	}

	maxPayloadLength, _, subPayloadSize := c.GetRSAToPublicMessageLength()

	if len(payload) > maxPayloadLength {
		return nil, nil, nil, nonce, errors.New("the encrypted message must " +
			"be no longer than GetRSAToPublicMessageLength()")
	}

	// Do the multiple RSA encryption operations on a chunked payload
	singleEncryptedPayload = make([]byte, 0,
		calculateRsaToPublicPacketSize(c.RsaPubKeyLength, c.RSASubPayloads))

	// Prepend the public key
	publicWire := privKey.Public().MarshalWire()
	singleEncryptedPayload = append(singleEncryptedPayload, publicWire...)

	// Encrypt and append the encrypted payloads
	h, _ := channelHash(nil)
	for n := 0; n < c.RSASubPayloads; n++ {
		h.Reset()
		subsample := permissiveSubsample(payload, subPayloadSize, n)
		innerCiphertext, err2 :=
			privKey.EncryptOAEPMulticast(h, csprng, subsample, c.label())
		if err2 != nil {
			return nil, nil, nil, format.Fingerprint{},
				errors.WithMessagef(err2, "Failed to encrypt asymmetric "+
					"broadcast message for subpayload %d", n)
		}
		singleEncryptedPayload =
			append(singleEncryptedPayload, innerCiphertext...)
	}

	// Symmetric encrypt the resulting payload
	doubleEncryptedPayload, mac, nonce, err =
		c.EncryptSymmetric(singleEncryptedPayload, outerPayloadSize, csprng)
	return singleEncryptedPayload, doubleEncryptedPayload, mac, nonce, err
}

// DecryptRSAToPublic decrypts an RSAToPublic message, dealing with both the
// symmetric and asymmetric components.
//
// It will reject messages if they are not encrypted with the channel's public
// key.
func (c *Channel) DecryptRSAToPublic(payload, mac []byte,
	nonce format.Fingerprint) (decrypted, innerCiphertext []byte, err error) {
	// Decrypt the symmetric payload
	// Note: MAC verification only proves the sender knows the channels secret,
	// not that they are the holder of the private key
	innerCiphertext, err = c.DecryptSymmetric(payload, mac, nonce)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt inner ciphertext
	decrypted, err = c.DecryptRSAToPublicInner(innerCiphertext)

	return decrypted, innerCiphertext, err
}

// DecryptRSAToPublicInner decrypts the inner ciphertext found inside an
// RSAToPublic message.
//
// This is the inner decryption function for DecryptRSAToPublic. It should only
// be called in special cases to decrypt a message that has already had the
// first layer of encryption removed.
func (c *Channel) DecryptRSAToPublicInner(innerCiphertext []byte) ([]byte, error) {
	s := rsa.GetScheme()

	// Check that the message's public key matches the channel's public key
	wireProtocolLength := s.GetMarshalWireLength(c.RsaPubKeyLength)
	rsaPubKey, err :=
		s.UnmarshalPublicKeyWire(innerCiphertext[:wireProtocolLength])
	if err != nil {
		return nil, err
	}
	if !c.IsPublicKey(rsaPubKey) {
		return nil, errors.New("public key does not match our public key hash")
	}

	// Chunk up the remaining payload into each RSA decryption and decrypt them
	h, err := channelHash(nil)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	rsaToPublicLength, _, _ := c.GetRSAToPublicMessageLength()
	decrypted := make([]byte, 0, rsaToPublicLength)
	for n := 0; n < c.RSASubPayloads; n++ {
		cypherText := permissiveSubsample(
			innerCiphertext[wireProtocolLength:], c.RsaPubKeyLength, n)
		decryptedPart, err2 :=
			rsaPubKey.DecryptOAEPMulticast(h, cypherText, c.label())
		if err2 != nil {
			return nil, errors.Wrapf(err2,
				"failed to decrypt sub-payload %d of %d", n, c.RSASubPayloads)
		}
		decrypted = append(decrypted, decryptedPart...)
	}

	return decrypted, nil
}

// GetRSAToPrivateMessageLength returns the size of the internal payload for
// RSAtoPublic encrypted messages. It returns the total size, the number of
// sub-payloads, and the size of each sub-payloads.
func (c *Channel) GetRSAToPrivateMessageLength() (size int, numSubPayloads int,
	subPayloadSize int) {
	// Get the number of bytes in each sub-payload
	h, _ := channelHash(nil)
	subPayloadSize = rsa.GetMaxOEAPPayloadSize(h, c.RsaPubKeyLength)

	// Private has room for an extra sub-payload because it does not transmit
	// the public key like Public
	numSubPayloads = c.RSASubPayloads + 1
	size = subPayloadSize * numSubPayloads
	return
}

// EncryptRSAToPrivate encrypts the given plaintext with the given
// RSA public key. The payload must not be longer than
// Channel.GetRSAToPrivateMessageLength()
func (c *Channel) EncryptRSAToPrivate(payload []byte, pubkey rsa.PublicKey,
	outerPayloadSize int, rng csprng.Source) (
	doubleEncryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	// Check they are using the proper key
	if !c.IsPublicKey(pubkey) {
		return nil, nil, nonce, errors.New("private key does not derive a " +
			"public key whose hash matches our public key hash")
	}

	maxPayloadLength, numSubPayloads, subPayloadSize :=
		c.GetRSAToPrivateMessageLength()

	if len(payload) > maxPayloadLength {
		return nil, nil, nonce, errors.New("the " +
			"encrypted message must be no longer than " +
			"GetRSAToPrivateMessageLength()")
	}

	// Do the multiple RSA encryption operations on a chunked payload
	singleEncryptedPayload := make([]byte, 0,
		calculateRsaToPrivatePacketSize(c.RsaPubKeyLength, numSubPayloads))

	// Encrypt and append the encrypted payloads
	h, _ := channelHash(nil)
	for n := 0; n < numSubPayloads; n++ {
		h.Reset()
		innerCiphertext, err := pubkey.EncryptOAEP(h,
			rng, permissiveSubsample(payload, subPayloadSize, n), c.label())
		if err != nil {
			return nil, nil, format.Fingerprint{},
				errors.WithMessagef(err, "Failed to encrypt asymmetric "+
					"broadcast message for subpayload %d", n)
		}
		singleEncryptedPayload = append(singleEncryptedPayload, innerCiphertext...)
	}

	// Symmetric encrypt the resulting payload
	doubleEncryptedPayload, mac, nonce, err = c.EncryptSymmetric(
		singleEncryptedPayload, outerPayloadSize, rng)
	return
}

// DecryptRSAToPrivate decrypts an RSAToPublic message, dealing with both the
// symmetric and asymmetric components.
//
// It will reject messages if they are not encrypted with the channel's public
// key.
func (c *Channel) DecryptRSAToPrivate(private rsa.PrivateKey, payload []byte,
	mac []byte, nonce format.Fingerprint) ([]byte, error) {
	// Decrypt the symmetric payload
	// Note: MAC verification only proves the sender knows the channels secret,
	// not that they are the holder of the private key
	innerCiphertext, err := c.DecryptSymmetric(payload, mac, nonce)
	if err != nil {
		return nil, err
	}

	// Chunk up the remaining payload into each RSA decryption and decrypt them
	h, _ := channelHash(nil)
	rsaToPublicLength, numSubPayloads, _ := c.GetRSAToPrivateMessageLength()
	decrypted := make([]byte, 0, rsaToPublicLength)
	for n := 0; n < numSubPayloads; n++ {
		cypherText := permissiveSubsample(innerCiphertext, c.RsaPubKeyLength, n)
		decryptedPart, err := private.DecryptOAEP(h, nil, cypherText,
			c.label())
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, decryptedPart...)
	}

	return decrypted, nil
}

// permissiveSubsample returns the nth subsample of size s in b. Returns short
// or empty subsamples if b is not long enough.
func permissiveSubsample(b []byte, size, n int) []byte {
	begin := n * size
	end := (n + 1) * size
	if begin > len(b) {
		return make([]byte, 0)
	} else if size > len(b[begin:]) {
		return b[begin:]
	} else {
		return b[begin:end]
	}
}
