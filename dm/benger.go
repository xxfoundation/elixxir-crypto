////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/hmac"

	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
)

// benger code is an hmac, but we do not call it that because it does
// not authenticate with the key of the message. Instead, it proves
// that the sender knows the private key of the public key included in
// the message. This prevents a third party from sending someone elses
// public key, making it appear to the user that the true the sender
// of a given message is someone else. It is similar to the sender
// signing the message they sent with their static public key.

// isValidBengerCode checks if the benger code is valid
func isValidBengerCode(readCode, key, msg []byte) bool {
	derivBengerCode := makeBengerCode(key, msg)
	if !hmac.Equal(readCode, derivBengerCode) {
		jww.DEBUG.Printf("[DM] failed benger mac check: %v != %v",
			readCode, derivBengerCode)
		return false
	}
	return true
}

// makeBengerCode is a helper to create a simple keyed hash This is
// the hash of a derived secret of both published public keys (not the
// keys used to encryption the message) + message embedded in a noise
// protocol message, which limits message sending to the sender or
// receiver of the message.
func makeBengerCode(key, msg []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(key)
	h.Write(msg)
	r := h.Sum(nil)[:bengerCodeSize]
	return r
}
