package broadcast

import (
	"bytes"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
)


// IsPublicKey returns true if the passed public key is the public key for the
// given channel
func (c *Channel) IsPublicKey(publicKey rsa.PublicKey) bool {
	if bytes.Equal(c.RsaPubKeyHash, hashSecret(publicKey.GetN().Bytes())) {
		return true
	}
	return false
}

// GetRSAToPublicMessageLength returns the size of the internal payload for
// RSAtoPublic encrypted messages. It returns the total size, the number of
// subpayloads, and the size of each subpayloads
func (c *Channel) GetRSAToPublicMessageLength() (size int, numSubPayloads int,
	subPayloadSize int) {
	// get the number of bytes in each subpayload
	h, _ := channelHash(nil)
	subPayloadSize = rsa.GetMaxOEAPPayloadSize(h,c.RsaPubKeyLength)
	numSubPayloads = c.RSASubPayloads
	size = subPayloadSize*numSubPayloads
	return
}

// EncryptRSAToPublic encrypts the payload with the private key. The payload
// must not be longer than Channel.GetRSAToPublicMessageLength().
// symmetric{pubkey|(rsa{p[0]}|rsa{p[1]}|...|rsa0{p[n]})|padding}
func (c *Channel) EncryptRSAToPublic(payload []byte, privkey rsa.PrivateKey,
	outerPayloadSize int, csprng csprng.Source) (
	doubleEncryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	// check they are using the proper key
	if !c.IsPublicKey(privkey.Public()) {
		return nil, nil, nonce, errors.New("private " +
			"key does not derive a public key whose hash matches our public key hash")
	}

	maxPayloadLength, _, subpayloadSize := c.GetRSAToPublicMessageLength()

	if len(payload)>maxPayloadLength{
		return nil, nil, nonce, errors.New("the " +
			"encrypted message must be no longer than " +
			"GetRSAToPublicMessageLength()")
	}

	//do the multiple RSA encryptions on a chunked payload
	singleEncryptedPayload := make([]byte, 0,
		calculateRsaToPublicPacketSize(c.RsaPubKeyLength, c.RSASubPayloads))

	//prepend the public key
	singleEncryptedPayload = append(singleEncryptedPayload,privkey.Public().MarshalWire()...)

	//encrypt and append the encrypted payloads
	h, _ := channelHash(nil)
	for n:=0;n<c.RSASubPayloads;n++{
		h.Reset()
		innerCiphertext, err := privkey.EncryptOAEPMulticast(h,
			csprng, permissiveSubsample(singleEncryptedPayload,subpayloadSize,n), c.label())
		if err != nil {
			return nil, nil, format.Fingerprint{},
			errors.WithMessagef(err, "Failed to encrypt asymmetric " +
				"broadcast message for subpayload %d", n)
		}
		singleEncryptedPayload = append(singleEncryptedPayload, innerCiphertext...)
	}

	//symmetric encrypt the resulting payload
	doubleEncryptedPayload, mac, nonce, err = c.EncryptSymmetric(
		singleEncryptedPayload, outerPayloadSize, csprng)
	return
}

// DecryptRSAToPublic decrypts an RSAToPublic message, dealing with both the symmetric
// and asymmetric components
// it will reject messages if they are not encrypted with the channel's public key
func (c *Channel) DecryptRSAToPublic(payload []byte, mac []byte, nonce format.Fingerprint) ([]byte, error) {
	// decrypt the symmetric payload
	// note: mac verification only proves the sender knows the channels secret,
	// not that they are the holder of the private key
	innerCiphertext, err := c.DecryptSymmetric(payload, mac, nonce)
	if err != nil {
		return nil, err
	}

	s := rsa.GetScheme()

	// check that the message's public key matches the channel's
	wireProtocolLength := s.GetMarshalWireLength(c.RsaPubKeyLength)
	rsaPubKey, err := s.UnmarshalPublicKeyWire(innerCiphertext[:wireProtocolLength])
	if err != nil {
		return nil, err
	}

	if !c.IsPublicKey(rsaPubKey) {
		return nil, errors.New("public key does not match our public " +
			"key hash")
	}

	// chunk up the remaining payload into each RSA decryption and decrypt them
	h, _ := channelHash(nil)
	rsaToPublicLength, _, _ := c.GetRSAToPublicMessageLength()
	decrypted := make([]byte, 0, rsaToPublicLength)
	for n:=0; n<c.RSASubPayloads;n++{
		cypherText := permissiveSubsample(innerCiphertext[wireProtocolLength:],c.RsaPubKeyLength,n)
		decryptedPart, err := rsaPubKey.DecryptOAEPMulticast(h, cypherText, c.label())
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, decryptedPart...)
	}

	return decrypted, nil
}


// GetRSAToPrivateMessageLength returns the size of the internal payload for
// RSAtoPublic encrypted messages. It returns the total size, the number of
// subpayloads, and the size of each subpayloads
func (c *Channel) GetRSAToPrivateMessageLength() (size int, numSubPayloads int,
	subPayloadSize int) {
	// get the number of bytes in each subpayload
	h, _ := channelHash(nil)
	subPayloadSize = rsa.GetMaxOEAPPayloadSize(h,c.RsaPubKeyLength)
	// to private has room for an extra subpayload because it does not
	// transmit the public key like Public
	numSubPayloads = c.RSASubPayloads+1
	size = subPayloadSize*numSubPayloads
	return
}


// EncryptRSAToPrivate encrypts the given plaintext with the given
// RSA public key. The payload must not be longer than
// Channel.GetRSAToPrivateMessageLength()
func (c *Channel) EncryptRSAToPrivate(payload []byte, pubkey rsa.PublicKey,
	outerPayloadSize int, rng csprng.Source) (
	doubleEncryptedPayload, mac []byte, nonce format.Fingerprint, err error) {

	// check they are using the proper key
	if !c.IsPublicKey(pubkey) {
		return nil, nil, nonce, errors.New("private " +
			"key does not derive a public key whose hash matches our public key hash")
	}

	maxPayloadLength, numSubPayloads, subpayloadSize := c.GetRSAToPrivateMessageLength()

	if len(payload)>maxPayloadLength{
		return nil, nil, nonce, errors.New("the " +
			"encrypted message must be no longer than " +
			"GetRSAToPrivateMessageLength()")
	}

	//do the multiple RSA encryptions on a chunked payload
	singleEncryptedPayload := make([]byte, 0,
		calculateRsaToPrivatePacketSize(c.RsaPubKeyLength, c.RSASubPayloads))

	//encrypt and append the encrypted payloads
	h, _ := channelHash(nil)
	for n:=0;n<numSubPayloads;n++{
		h.Reset()
		innerCiphertext, err := pubkey.EncryptOAEP(h,
			rng, permissiveSubsample(singleEncryptedPayload,subpayloadSize,n), c.label())
		if err != nil {
			return nil, nil, format.Fingerprint{},
				errors.WithMessagef(err, "Failed to encrypt asymmetric " +
					"broadcast message for subpayload %d", n)
		}
		singleEncryptedPayload = append(singleEncryptedPayload, innerCiphertext...)
	}

	//symmetric encrypt the resulting payload
	doubleEncryptedPayload, mac, nonce, err = c.EncryptSymmetric(
		singleEncryptedPayload, outerPayloadSize, rng)
	return
}

// DecryptRSAToPrivate decrypts an RSAToPublic message, dealing with both the symmetric
// and asymmetric components
// it will reject messages if they are not encrypted with the channel's public key
func (c *Channel) DecryptRSAToPrivate(private rsa.PrivateKey, payload []byte,
	mac []byte, nonce format.Fingerprint) ([]byte, error) {
	// decrypt the symmetric payload
	// note: mac verification only proves the sender knows the channels secret,
	// not that they are the holder of the private key
	innerCiphertext, err := c.DecryptSymmetric(payload, mac, nonce)
	if err != nil {
		return nil, err
	}


	// chunk up the remaining payload into each RSA decryption and decrypt them
	h, _ := channelHash(nil)
	rsaToPublicLength, numSubPayloads, _ := c.GetRSAToPrivateMessageLength()
	decrypted := make([]byte, 0, rsaToPublicLength)
	for n:=0; n<numSubPayloads;n++{
		cypherText := permissiveSubsample(innerCiphertext,c.RsaPubKeyLength,n)
		decryptedPart, err := private.DecryptOAEP(h, nil, cypherText,
			c.label())
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, decryptedPart...)
	}

	return decrypted, nil
}


// permissiveSubsample returns the nth subsample of size s in b, returning short or
// empty subsamples if b is not long enough
func permissiveSubsample(b []byte, size, n int)[]byte{
	begin := n*size
	end := (n+1)*size
	if begin>len(b){
		return nil
	}else if end>len(b){
		return b[begin:]
	}else{
		return b[begin:end]
	}
}