////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"io"
	"syscall/js"
)

// Generate generates an RSA keypair of the given bit size using the random
// source random (for example, crypto/rand.Reader).
func (*scheme) Generate(_ io.Reader, bits int) (PrivateKey, error) {
	if bits < softMinRSABitLen {
		jww.WARN.Printf(softMinRSABitLenWarn, bits, softMinRSABitLen)
	}

	algorithm := makeRsaHashedKeyGenParams(
		"RSASSA-PKCS1-v1_5", bits, []byte{0x01, 0x00, 0x01}, "SHA-256")

	result, awaitErr := Await(subtleCrypto.Call("generateKey",
		algorithm, true, array.New("sign")))
	if awaitErr != nil {
		return nil, handleJsError(awaitErr[0])
	}

	result, awaitErr = Await(
		subtleCrypto.Call("exportKey", "pkcs8", result[0].Get("privateKey")))
	if awaitErr != nil {
		return nil, handleJsError(awaitErr[0])
	}

	keyData := CopyBytesToGo(Uint8Array.New(result[0]))

	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, errors.Errorf("could not decode key from PEM: %+v", err)
	}

	goPriv, success := key.(*gorsa.PrivateKey)
	if !success {
		return nil, errors.New("decoded key is not an RSA key")
	}

	return makePrivateKey(*goPriv)
}

////////////////////////////////////////////////////////////////////////////////
// Javascript Utilities                                                       //
////////////////////////////////////////////////////////////////////////////////

// makeRsaHashedKeyGenParams creates a Javascript RsaHashedKeyGenParams object.
//
// scheme is the name of the padding scheme to use. This can be
// "RSASSA-PKCS1-v1_5", "RSA-PSS", or "RSA-OAEP".
//
// modulusLength is the length, in bits, of the RSA modulus.
//
// hash is the name of the digest function to use. This can be "SHA-1"
// (discouraged), "SHA-256", "SHA-384", or "SHA-512".
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
func makeRsaHashedKeyGenParams(scheme string, modulusLength int,
	publicExponent []byte, hash string) js.Value {
	algorithm := object.New()
	algorithm.Set("name", scheme)
	algorithm.Set("modulusLength", modulusLength)
	algorithm.Set("publicExponent", CopyBytesToJS(publicExponent))
	algorithm.Set("hash", hash)
	return algorithm
}
