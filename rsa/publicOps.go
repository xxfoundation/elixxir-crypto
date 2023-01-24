////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// This file is compiled for all architectures except WebAssembly.
//go:build !js || !wasm

package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"hash"
	"io"
)

// EncryptOAEP encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
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
// This function uses the Go standard crypto/rsa implementation.
func (pub *public) EncryptOAEP(hash hash.Hash, random io.Reader, msg []byte,
	label []byte) ([]byte, error) {
	return gorsa.EncryptOAEP(hash, random, &pub.PublicKey, msg, label)
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
//
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero, then hashed is used directly.
// This isn't advisable except for interoperability.
//
// This function uses the Go standard crypto/rsa implementation.
func (pub *public) VerifyPKCS1v15(
	hash crypto.Hash, hashed []byte, sig []byte) error {
	return gorsa.VerifyPKCS1v15(&pub.PublicKey, hash, hashed, sig)
}

// VerifyPSS verifies a PSS signature.
//
// A valid signature is indicated by returning a nil error. digest must be the
// result of hashing the input message using the given hash function. The opts
// argument may be nil; in which case, sensible defaults are used. opts.Hash is
// ignored.
//
// This function uses the Go standard crypto/rsa implementation.
func (pub *public) VerifyPSS(
	hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error {
	if opts == nil {
		opts = NewDefaultPSSOptions()
		opts.Hash = hash
	}
	return gorsa.VerifyPSS(&pub.PublicKey, hash, digest, sig, &opts.PSSOptions)
}
