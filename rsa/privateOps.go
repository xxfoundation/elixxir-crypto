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

// SignPSS calculates the signature of digest using PSS.
//
// hashed must be the result of hashing the input message using the given hash
// function. The opts argument may be nil, in which case sensible defaults are
// used. If opts.Hash is set, it overrides hash.
//
// This function uses the Go standard crypto/rsa implementation.
func (priv *private) SignPSS(random io.Reader, hash crypto.Hash, hashed []byte,
	opts *PSSOptions) ([]byte, error) {
	if opts == nil {
		opts = NewDefaultPSSOptions()
		opts.Hash = hash
	}

	return gorsa.SignPSS(
		random, &priv.PrivateKey, hash, hashed, &opts.PSSOptions)
}

// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN
// from RSA PKCS #1 v1.5. Note that hashed must be the result of hashing the
// input message using the given hash function. If hash is zero, hashed is
// signed directly. This isn't advisable except for interoperability.
//
// If random is not nil, then RSA blinding will be used to avoid timing
// side-channel attacks.
//
// This function is deterministic. Thus, if the set of possible messages is
// small, an attacker may be able to build a map from messages to signatures and
// identify the signed messages. As ever, signatures provide authenticity, not
// confidentiality.
//
// This function uses the Go standard crypto/rsa implementation.
func (priv *private) SignPKCS1v15(
	random io.Reader, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return gorsa.SignPKCS1v15(random, &priv.PrivateKey, hash, hashed)
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
// This function uses the Go standard crypto/rsa implementation.
func (priv *private) DecryptOAEP(hash hash.Hash, random io.Reader,
	ciphertext []byte, label []byte) ([]byte, error) {
	return gorsa.DecryptOAEP(hash, random, &priv.PrivateKey, ciphertext, label)
}
