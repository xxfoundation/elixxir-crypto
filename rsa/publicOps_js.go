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

// ErrVerification represents a failure to verify a signature by a Javascript
// SubtleCrypto operation.
//
// This error is modeled on crypto/rsa.ErrVerification. It is deliberately vague
// to avoid adaptive attacks.
var ErrVerification = errors.New("Javascript SubtleCrypto: verification error")

// EncryptOAEP encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use SHA-256.
//
// The random parameter is not used. Instead, the browser will provide a source
// of entropy to ensure that encrypting the same message twice doesn't result in
// the same ciphertext.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to encrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
func (pub *public) EncryptOAEP(
	_ hash.Hash, _ io.Reader, msg []byte, label []byte) ([]byte, error) {

	algorithm := makeRsaOaepParams(label)

	key, err := pub.getOAEP()
	if err != nil {
		return nil, err
	}

	result, awaitErr := Await(subtleCrypto.Call("encrypt",
		algorithm, key, CopyBytesToJS(msg)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return CopyBytesToGo(Uint8Array.New(result[0])), nil
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
//
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error.
//
// hash must be crypto.SHA256 because Javascript's SubtleCrypto only supports
// SHA-256. An error is returned for all other hashing algorithms.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
func (pub *public) VerifyPKCS1v15(
	hash crypto.Hash, hashed []byte, sig []byte) error {
	if hash != crypto.SHA256 {
		return ErrInvalidHash
	}

	key, err := pub.getPKCS1()
	if err != nil {
		return err
	}

	result, awaitErr := Await(subtleCrypto.Call("verify",
		"RSASSA-PKCS1-v1_5", key, CopyBytesToJS(sig), CopyBytesToJS(hashed)))
	if awaitErr != nil {
		return js.Error{Value: awaitErr[0]}
	}

	if !result[0].Bool() {
		return ErrVerification
	}

	return nil
}

// VerifyPSS verifies a PSS signature.
//
// A valid signature is indicated by returning a nil error. digest must be the
// result of hashing the input message using the given hash function. The opts
// argument may be nil; in which case, sensible defaults are used.
//
// hash (and opts.Hash if opts is not nil) must be crypto.SHA256 because
// Javascript's SubtleCrypto only supports SHA-256. An error is returned for all
// other hashing algorithms. If opts.Hash is set, it overrides hash.
//
// This function uses the Javascript SubtleCrypto implementation.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
func (pub *public) VerifyPSS(
	hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error {

	if (opts == nil && hash != crypto.SHA256) ||
		(opts != nil && opts.Hash != crypto.SHA256) {
		return ErrInvalidHash
	}

	if opts == nil {
		opts = NewDefaultPSSOptions()
	}

	// Set the salt length to the digest size of SHA-256.
	if opts.SaltLength == gorsa.PSSSaltLengthEqualsHash {
		opts.SaltLength = 32
	}

	algorithm := makeRsaPssParams(opts.SaltLength)

	key, err := pub.getPSS()
	if err != nil {
		return err
	}

	result, awaitErr := Await(subtleCrypto.Call("verify",
		algorithm, key, CopyBytesToJS(sig), CopyBytesToJS(digest)))
	if awaitErr != nil {
		return js.Error{Value: awaitErr[0]}
	}

	if !result[0].Bool() {
		return ErrVerification
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Javascript Utilities                                                       //
////////////////////////////////////////////////////////////////////////////////

// getPSS returns the RSA-PSS variant of the Javascript CryptoKey object. This
// key can only be used for signing.
func (pub *public) getPSS() (js.Value, error) {
	return pub.getRsaCryptoKey("RSA-PSS", "SHA-256", "verify")
}

// getPKCS1 returns the RSASSA-PKCS1-v1_5 variant of the Javascript CryptoKey
// object. This key can only be used for signing.
func (pub *public) getPKCS1() (js.Value, error) {
	return pub.getRsaCryptoKey("RSASSA-PKCS1-v1_5", "SHA-256", "verify")
}

// getOAEP returns the RSA-OAEP variant of the Javascript CryptoKey object. This
// key can only be used for decrypting.
func (pub *public) getOAEP() (js.Value, error) {
	return pub.getRsaCryptoKey("RSA-OAEP", "SHA-256", "encrypt")
}

// getRsaCryptoKey imports the Go crypto/rsa PublicKey into a Javascript
// CryptoKey object. CryptoKey require specifying the scheme, digest type, and
// usages on import. Thus, a different CryptoKey is required for different
// cryptographic operations.
//
// The scheme is the padding scheme to use and hash is the digest function to
// use (refer to makeRsaHashedImportParams for more information). keyUsages
// should be a string or list of strings indicating how the key will be used.
func (pub *public) getRsaCryptoKey(
	scheme, hash string, keyUsages ...any) (js.Value, error) {
	key, err := x509.MarshalPKIXPublicKey(&pub.PublicKey)
	if err != nil {
		return js.Value{}, err
	}

	algorithm := makeRsaHashedImportParams(scheme, hash)

	result, awaitErr := Await(subtleCrypto.Call("importKey",
		"spki", CopyBytesToJS(key), algorithm, true, array.New(keyUsages...)))
	if awaitErr != nil {
		return js.Value{}, js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}
