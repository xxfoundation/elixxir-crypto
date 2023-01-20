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

func isValidBengerCode(readCode, key, msg []byte) bool {
	derivBengerCode := makeBengerCode(key, msg)
	if !hmac.Equal(readCode, derivBengerCode) {
		jww.DEBUG.Printf("[DM] failed benger mac check: %v != %v",
			readCode, derivBengerCode)
		return false
	}
	return true
}

// makeBengerCode is a helper to create a simple keyed hash
// This is the hash of a derived secret + message embedded in
// a noise protocol message, which limits spoofed message sending
// to the sender or receiver of the message.
func makeBengerCode(key, msg []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(key)
	r := h.Sum(msg)[:bengerCodeSize]
	return r
}
