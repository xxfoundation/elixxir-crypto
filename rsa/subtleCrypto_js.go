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

var sc subtleCrypto

type subtleCrypto struct {
	js.Value
}

func init() {
	sc.Value = js.Global().Get("crypto").Get("subtle")
	if sc.IsUndefined() {
		err := errors.New("SubtleCrypto unavailable; " +
			"is a secure context (TLS/https) enabled?")
		jww.FATAL.Printf("%+v", err)
		exception.ThrowTrace(err)
	}
}

// encrypt encrypts data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
func (sc *subtleCrypto) encrypt(algorithm map[string]any, key js.Value,
	plaintext []byte) (ciphertext []byte, err error) {
	promise, err := sc.callCatch("encrypt",
		algorithm, key, utils.CopyBytesToJS(plaintext))
	if err != nil {
		return nil, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// decrypt decrypts data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
func (sc *subtleCrypto) decrypt(algorithm map[string]any, key js.Value,
	ciphertext []byte) (plaintext []byte, err error) {
	promise, err := sc.callCatch("decrypt",
		algorithm, key, utils.CopyBytesToJS(ciphertext))
	if err != nil {
		return nil, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// sign generates a digital signature using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
func (sc *subtleCrypto) sign(algorithm map[string]any, key js.Value,
	data []byte) (signature []byte, err error) {
	promise, err := sc.callCatch("sign",
		algorithm, key, utils.CopyBytesToJS(data))
	if err != nil {
		return nil, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// verify verifies a digital signature using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
func (sc *subtleCrypto) verify(algorithm map[string]any, key js.Value,
	signature, data []byte) (valid bool, err error) {
	promise, err := sc.callCatch("verify",
		algorithm, key, utils.CopyBytesToJS(signature), utils.CopyBytesToJS(data))
	if err != nil {
		return false, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return false, js.Error{Value: awaitErr[0]}
	}

	return result[0].Bool(), nil
}

// digest generates a digest of the given data using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
func (sc *subtleCrypto) digest(algorithm map[string]any, data []byte) (
	digest []byte, err error) {
	promise, err := sc.callCatch("digest",
		algorithm, utils.CopyBytesToJS(data))
	if err != nil {
		return nil, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// generateKey generates a new key (for symmetric algorithms) or key pair (for
// public-key algorithms) using SubtleCrypto.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
func (sc *subtleCrypto) generateKey(algorithm map[string]any, extractable bool,
	keyUsages ...any) (key js.Value, err error) {
	promise, err := sc.callCatch("generateKey",
		algorithm, extractable, keyUsages)
	if err != nil {
		return js.Undefined(), err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return js.Undefined(), js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}

// importKey takes a key in an external, portable format and return a CryptoKey
// object that can be used in the Web Crypto API.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
func (sc *subtleCrypto) importKey(format string, keyData []byte,
	algorithm map[string]any, extractable bool, keyUsages ...any) (
	key js.Value, err error) {
	promise, err := sc.callCatch("importKey",
		format, utils.CopyBytesToJS(keyData), algorithm, extractable, keyUsages)
	if err != nil {
		return js.Undefined(), err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return js.Undefined(), js.Error{Value: awaitErr[0]}
	}

	return result[0], nil
}

// exportKey returns the CryptoKey object in an external, portable format.
//
// Doc: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
func (sc *subtleCrypto) exportKey(format string, key js.Value) (
	portableKey []byte, err error) {
	promise, err := sc.callCatch("exportKey", format, key)
	if err != nil {
		return nil, err
	}
	result, awaitErr := utils.Await(promise)
	if awaitErr != nil {
		return nil, js.Error{Value: awaitErr[0]}
	}

	return utils.CopyBytesToGo(utils.Uint8Array.New(result[0])), nil
}

// callCatch does a JavaScript call to the method m of SubtleCrypto with the
// given arguments. It catches and returns all thrown exceptions.
func (sc *subtleCrypto) callCatch(
	m string, args ...any) (result js.Value, err error) {
	defer exception.Catch(&err)
	return sc.Value.Call(m, args...), nil
}
