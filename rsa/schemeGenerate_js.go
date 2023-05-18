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
	"io"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/elixxir/wasm-utils/utils"
)

// Generate generates an RSA keypair of the given bit size using the random
// source random (for example, crypto/rand.Reader).
func (*scheme) Generate(_ io.Reader, bits int) (PrivateKey, error) {
	if bits < softMinRSABitLen {
		jww.WARN.Printf(softMinRSABitLenWarn, bits, softMinRSABitLen)
	}

	algorithm := makeRsaHashedKeyGenParams(
		"RSASSA-PKCS1-v1_5", bits, []byte{0x01, 0x00, 0x01}, "SHA-256")

	result, err := subtleCrypto.GenerateKey(algorithm, true, "sign")
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate RSA key")
	}

	keyData, err := subtleCrypto.ExportKey("pkcs8", result.Get("privateKey"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to export key as pkcs8")
	}

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
	publicExponent []byte, hash string) map[string]any {
	return map[string]any{
		"name":           scheme,
		"modulusLength":  modulusLength,
		"publicExponent": utils.CopyBytesToJS(publicExponent),
		"hash":           hash,
	}
}
