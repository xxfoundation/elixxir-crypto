////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"syscall/js"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/elixxir/wasm-utils/exception"
	"gitlab.com/elixxir/wasm-utils/utils"
)

var subtleCrypto SubtleCrypto

type SubtleCrypto struct {
	js.Value
}

func init() {
	subtleCrypto.Value = js.Global().Get("crypto").Get("subtle")
	if subtleCrypto.IsUndefined() {
		err := errors.New("SubtleCrypto unavailable; " +
			"is a secure context (TLS/https) enabled?")
		jww.FATAL.Printf("%+v", err)
		exception.ThrowTrace(err)
	}
}

// Encrypt encrypts data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
func (sc *SubtleCrypto) Encrypt(algorithm map[string]any, key js.Value,
	plaintext []byte) (ciphertext []byte, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("encrypt",
		algorithm, key, utils.CopyBytesToJS(plaintext)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// Decrypt decrypts data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
func (sc *SubtleCrypto) Decrypt(algorithm map[string]any, key js.Value,
	ciphertext []byte) (plaintext []byte, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("decrypt",
		algorithm, key, utils.CopyBytesToJS(ciphertext)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// Sign generates a digital signature using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
func (sc *SubtleCrypto) Sign(algorithm map[string]any, key js.Value,
	data []byte) (signature []byte, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("sign",
		algorithm, key, utils.CopyBytesToJS(data)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// Verify verifies a digital signature using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
func (sc *SubtleCrypto) Verify(algorithm map[string]any, key js.Value,
	signature, data []byte) (valid bool, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("verify",
		algorithm, key, utils.CopyBytesToJS(signature),
		utils.CopyBytesToJS(data)))
	if awaitErr != nil {
		return false, js.Error{Value: awaitErr[0]}
	}

	return result[0].Bool(), nil
}

// Digest generates a digest of the given data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
func (sc *SubtleCrypto) Digest(algorithm map[string]any, data []byte) (
	digest []byte, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("digest",
		algorithm, utils.CopyBytesToJS(data)))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// GenerateKey generates a new key (for symmetric algorithms) or key pair (for
// public-key algorithms) using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
func (sc *SubtleCrypto) GenerateKey(algorithm map[string]any, extractable bool,
	keyUsages ...any) (key js.Value, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("generateKey",
		algorithm, extractable, keyUsages))
	if awaitErr != nil {
		return js.Value{}, js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}

// ImportKey takes a key in an external, portable format and return a CryptoKey
// object that can be used in the Web Crypto API.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
func (sc *SubtleCrypto) ImportKey(format string, keyData []byte,
	algorithm map[string]any, extractable bool, keyUsages ...any) (
	key js.Value, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("importKey",
		format, utils.CopyBytesToJS(keyData), algorithm, extractable, keyUsages))
	if awaitErr != nil {
		return js.Value{}, js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}

// ExportKey returns the CryptoKey object in an external, portable format.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
func (sc *SubtleCrypto) ExportKey(format string, key js.Value) (
	portableKey []byte, err error) {
	defer exception.Catch(&err)
	result, awaitErr := utils.Await(sc.Value.Call("exportKey", format, key))
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}
