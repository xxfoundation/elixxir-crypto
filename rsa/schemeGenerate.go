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
	gorsa "crypto/rsa"
	"io"
)

// Generate generates an RSA keypair of the given bit size using the random
// source random (for example, crypto/rand.Reader).
//
// This function uses the Go standard crypto/rsa implementation.
func (*scheme) Generate(random io.Reader, bits int) (PrivateKey, error) {
	checkRSABitLen(bits)

	goPriv, err := gorsa.GenerateKey(random, bits)
	if err != nil {
		return nil, err
	}
	return makePrivateKey(*goPriv)
}
