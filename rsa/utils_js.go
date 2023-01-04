////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"syscall/js"
)

var (
	subtleCrypto = js.Global().Get("crypto").Get("subtle")
	array        = js.Global().Get("Array")

	// Object is the Javascript Object type. It is used to perform Object
	// operations on the Javascript layer.
	object = js.Global().Get("Object")

	// Uint8Array is the Javascript Uint8Array type. It is used to create new
	// Uint8Array.
	Uint8Array = js.Global().Get("Uint8Array")
)

// CopyBytesToGo copies the Uint8Array stored in the js.Value to []byte.
// This is a wrapper for js.CopyBytesToGo to make it more convenient.
func CopyBytesToGo(src js.Value) []byte {
	b := make([]byte, src.Length())
	js.CopyBytesToGo(b, src)
	return b
}

// CopyBytesToJS copies the []byte to a Uint8Array stored in a js.Value.
// This is a wrapper for js.CopyBytesToJS to make it more convenient.
func CopyBytesToJS(src []byte) js.Value {
	dst := Uint8Array.New(len(src))
	js.CopyBytesToJS(dst, src)
	return dst
}

// Await waits on a Javascript value. It blocks until the awaitable successfully
// resolves to the result or rejects to err.
//
// If there is a result, err will be nil and vice versa.
func Await(awaitable js.Value) (result []js.Value, err []js.Value) {
	then := make(chan []js.Value)
	defer close(then)
	thenFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		then <- args
		return nil
	})
	defer thenFunc.Release()

	catch := make(chan []js.Value)
	defer close(catch)
	catchFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		catch <- args
		return nil
	})
	defer catchFunc.Release()

	awaitable.Call("then", thenFunc).Call("catch", catchFunc)

	select {
	case result = <-then:
		return result, nil
	case err = <-catch:
		return nil, err
	}
}
