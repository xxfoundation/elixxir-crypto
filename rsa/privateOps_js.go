////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"hash"
	"io"
	"syscall/js"
)

// ErrInvalidHash represents a failure to use a valid hashing algorithm.
var ErrInvalidHash = errors.Errorf("%s hash required", crypto.SHA256)

// SignPSS calculates the signature of digest using PSS.
//
// hashed must be the result of hashing the input message using the given hash
// function. The opts argument may be nil, in which case sensible defaults are
// used.
//
// hash (and opts.Hash if opts is not nil) must be crypto.SHA256 because
// Javascript's SubtleCrypto only supports SHA-256. An error is returned for all
// other hashing algorithms. If opts.Hash is set, it overrides hash.
//
// random is not used. Instead, the browser's implementation is used.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
func (priv *private) SignPSS(_ io.Reader, hash crypto.Hash, hashed []byte,
	opts *PSSOptions) ([]byte, error) {

	if (opts == nil && hash != crypto.SHA256) ||
		(opts != nil && opts.Hash != crypto.SHA256) {
		return nil, ErrInvalidHash
	}

	if opts == nil {
		opts = NewDefaultPSSOptions()
	}

	// Set the salt length to the digest size of SHA-256.
	if opts.SaltLength == gorsa.PSSSaltLengthEqualsHash {
		opts.SaltLength = 32
	}

	algorithm := makeRsaPssParams(opts.SaltLength)

	key, err := priv.getPSS()
	if err != nil {
		return nil, err
	}

	result, awaitErr := Await(subtleCrypto.Call("sign",
		algorithm, key, CopyBytesToJS(hashed)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return CopyBytesToGo(Uint8Array.New(result[0])), nil
}

// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN
// from RSA PKCS #1 v1.5. Note that hashed must be the result of hashing the
// input message using the given hash function. If hash is zero, hashed is
// signed directly. This isn't advisable except for interoperability.
//
// This function is deterministic. Thus, if the set of possible messages is
// small, an attacker may be able to build a map from messages to signatures and
// identify the signed messages. As ever, signatures provide authenticity, not
// confidentiality.
//
// hash must be crypto.SHA256 because Javascript's SubtleCrypto only supports
// SHA-256. An error is returned for all other hashing algorithms.
//
// random is not used. Instead, the browser's implementation is used.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
func (priv *private) SignPKCS1v15(
	_ io.Reader, hash crypto.Hash, hashed []byte) ([]byte, error) {

	if hash != crypto.SHA256 {
		return nil, ErrInvalidHash
	}

	key, err := priv.getPKCS1()
	if err != nil {
		return nil, err
	}

	result, awaitErr := Await(subtleCrypto.Call("sign",
		"RSASSA-PKCS1-v1_5", key, CopyBytesToJS(hashed)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return CopyBytesToGo(Uint8Array.New(result[0])), nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter, if not nil, is used to blind the private-key operation
// and avoid timing side-channel attacks. Blinding is purely internal to this
// function – the random data need not match that used when encrypting.
//
// The label parameter must match the value given when encrypting. See
// PublicKey.EncryptOAEP for details.
//
// hash is always ignored. Instead, SHA-256 will always be used. random is also
// not used, instead the browsers implementation is used.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
func (priv *private) DecryptOAEP(
	_ hash.Hash, _ io.Reader, ciphertext []byte, label []byte) ([]byte, error) {

	algorithm := makeRsaOaepParams(label)

	key, err := priv.getOAEP()
	if err != nil {
		return nil, err
	}

	result, awaitErr := Await(subtleCrypto.Call("decrypt",
		algorithm, key, CopyBytesToJS(ciphertext)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return CopyBytesToGo(Uint8Array.New(result[0])), nil
}

////////////////////////////////////////////////////////////////////////////////
// Javascript Utilities                                                       //
////////////////////////////////////////////////////////////////////////////////

// getPSS returns the RSA-PSS variant of the Javascript CryptoKey object. This
// key can only be used for signing.
func (priv *private) getPSS() (js.Value, error) {
	return priv.getRsaCryptoKey("RSA-PSS", "SHA-256", "sign")
}

// getPKCS1 returns the RSASSA-PKCS1-v1_5 variant of the Javascript CryptoKey
// object. This key can only be used for signing.
func (priv *private) getPKCS1() (js.Value, error) {
	return priv.getRsaCryptoKey("RSASSA-PKCS1-v1_5", "SHA-256", "sign")
}

// getOAEP returns the RSA-OAEP variant of the Javascript CryptoKey object. This
// key can only be used for decrypting.
func (priv *private) getOAEP() (js.Value, error) {
	return priv.getRsaCryptoKey("RSA-OAEP", "SHA-256", "decrypt")
}

// getRsaCryptoKey imports the Go crypto/rsa PrivateKey into a Javascript
// CryptoKey object. CryptoKey require specifying the scheme, digest type, and
// usages on import. Thus, a different CryptoKey is required for different
// cryptographic operations.
//
// The scheme is the padding scheme to use and hash is the digest function to
// use (refer to makeRsaHashedImportParams for more information). keyUsages
// should be a string or list of strings indicating how the key will be used.
func (priv *private) getRsaCryptoKey(
	scheme, hash string, keyUsages ...any) (js.Value, error) {
	key, err := x509.MarshalPKCS8PrivateKey(&priv.PrivateKey)
	if err != nil {
		return js.Value{}, err
	}

	algorithm := makeRsaHashedImportParams(scheme, hash)

	result, awaitErr := Await(subtleCrypto.Call("importKey",
		"pkcs8", CopyBytesToJS(key), algorithm, true, array.New(keyUsages...)))
	if awaitErr != nil {
		return js.Value{}, js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}

// makeRsaHashedImportParams creates a Javascript RsaHashedImportParams object.
//
// scheme is the name of the padding scheme to use. This can be
// "RSASSA-PKCS1-v1_5", "RSA-PSS", or "RSA-OAEP".
//
// hash is the name of the digest function to use. This can be "SHA-1"
// (discouraged), "SHA-256", "SHA-384", or "SHA-512".
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedImportParams
func makeRsaHashedImportParams(scheme, hash string) js.Value {
	algorithm := object.New()
	algorithm.Set("name", scheme)
	algorithm.Set("hash", hash)
	return algorithm
}

// makeRsaPssParams creates a Javascript RsaPssParams object.
//
// saltLength is the length of the random salt to use, in bytes.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/RsaPssParams
func makeRsaPssParams(saltLength int) js.Value {
	algorithm := object.New()
	algorithm.Set("name", "RSA-PSS")
	algorithm.Set("saltLength", saltLength)
	return algorithm
}

// makeRsaOaepParams creates a Javascript object with the name and label fields
// required when encrypting/decrypting using an RSA-OAEP key.
//
// A digest of the label is part of the input to the encryption operation.
func makeRsaOaepParams(label []byte) js.Value {
	algorithm := object.New()
	algorithm.Set("name", "RSA-OAEP")
	algorithm.Set("label", CopyBytesToJS(label))
	return algorithm
}
