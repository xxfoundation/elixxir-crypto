////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"io"

	jww "github.com/spf13/jwalterweatherman"
)

// See length checking in RFC 3447 7.2.1-1
const MinPaddingStringLen = 8
const NumFixedPaddingLen = 3
const MinPaddingLen = MinPaddingStringLen + NumFixedPaddingLen

// Error case messages
var ErrMessageTooLong = errors.New("message too long")
var ErrEncMessageLength = errors.New("encoded message less than min. padding length")
var ErrPaddingPrefix = errors.New("padding prefix invalid")
var ErrPaddingContainsZero = errors.New("padding string contains a zero")
var ErrPaddingTerminator = errors.New("padding terminator invalid")

// PKCS 1.5 Pad using crypto.rand.Reader
func Pad(msg []byte, encMsgLen int) (encMsg []byte, err error) {
	// Client shouldn't need to choose RNG so use crypto.rand.Reader here
	return pad(msg, encMsgLen, rand.Reader)
}

// PKCS 1.5 Pad (See RFC 3447 7.2.1 https://tools.ietf.org/html/rfc3447#section-7.2.1)
func pad(msg []byte, encMsgLen int, rand io.Reader) (encMsg []byte, err error) {
	msgLen := len(msg)

	if msgLen > encMsgLen-MinPaddingLen {
		return nil, ErrMessageTooLong
	}

	// RFC 3447 7.2.1-2 defines the following padding format:
	// encMsg = 0x00 || 0x02 || paddingString || 0x00 || message
	encMsg = make([]byte, encMsgLen)

	// Set first two padding octets
	encMsg[0] = 0x00
	encMsg[1] = 0x02

	// Add non-zero padding string
	paddingString := encMsg[2:(encMsgLen - msgLen - 1)]
	nonZeroRandomBytes(paddingString, rand)

	// Add padding termination octet
	termInd := encMsgLen - msgLen - 1
	encMsg[termInd] = 0x00

	// Get region in encoded message buffer and copy the message into buffer
	msgBuffer := encMsg[encMsgLen-msgLen:]
	copy(msgBuffer, msg)

	return encMsg, nil
}

// PKCS 1.5 Unpad (See RFC 3447 7.2.1 https://tools.ietf.org/html/rfc3447#section-7.2.1)
func Unpad(encMsg []byte) (msg []byte, err error) {
	encMsgLen := len(encMsg)

	if encMsgLen < MinPaddingLen {
		return nil, ErrEncMessageLength
	}

	// RFC 3447 7.2.1-2 defines the following padding format:
	// encMsg = 0x00 || 0x02 || paddingString || 0x00 || message

	// Check padding prefix
	if !hmac.Equal(encMsg[0:2], []byte{0x00, 0x02}) {
		return nil, ErrPaddingPrefix
	}

	// Check that the smallest possible padding string contains non-zero octets.
	minPaddingStr := encMsg[2 : MinPaddingLen-1]
	for _, oct := range minPaddingStr {
		if oct == 0x00 {
			return nil, ErrPaddingContainsZero
		}
	}

	// Search for first zero octet after min. padding string and panic if not found.
	termInd := 0
	for i := MinPaddingLen - 1; i < len(encMsg); i++ {
		if encMsg[i] == 0x00 {
			jww.INFO.Printf("found end of padding in encoded message at %v", termInd)
			termInd = i
			break
		}
	}

	// If unable to find terminator then return an error
	if termInd == 0 {
		return nil, ErrPaddingTerminator
	}

	// Extract message after padding
	msg = encMsg[termInd+1:]

	return msg, nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
// Taken from x/crypto/openpgp/elgamal/elgamal.go and crypto/rsa/pkcs1v15.go
// and modified to explicitly panic on external Reader failure instead of returning an error
func nonZeroRandomBytes(s []byte, rand io.Reader) {
	// Fill slice with random octets (including zeros)
	_, err := io.ReadFull(rand, s)
	if err != nil {
		jww.FATAL.Panicf("error reading full length of buffer from rand Reader into slice: %v", err.Error())
	}

	for i := 0; i < len(s); i++ {
		// If a zero octet was added to slice, loop until it is replaced with a non-zero octet
		for s[i] == 0 {
			_, err := io.ReadFull(rand, s[i:i+1])
			if err != nil {
				jww.FATAL.Panicf("could not repolace zero octet with a non-zero octet: %v", err.Error())
			}
		}
	}
}
