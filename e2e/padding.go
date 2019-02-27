package e2e

import (
	"crypto/rand"
	jww "github.com/spf13/jwalterweatherman"
	"io"
)

// See length checking in RFC 3447 7.2.1-1
const MinPaddingStringLen= 8
const NumFixedPaddingLen = 3
const MinPaddingLen = MinPaddingStringLen + NumFixedPaddingLen


func Pad(msg []byte, encMsgLen int) (encMsg []byte) {
	return pad(msg, encMsgLen, rand.Reader)
}


// PKCS 1.5 Pad (See RFC 3447 7.2.1 https://tools.ietf.org/html/rfc3447#section-7.2.1)
func pad(msg []byte, encMsgLen int, rand io.Reader) (encMsg []byte) {
	msgLen := len(msg)

	if msgLen > encMsgLen - MinPaddingLen {
		jww.FATAL.Panicf("Could not add padding: message too long")
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
	msgBuffer := encMsg[encMsgLen - msgLen:]
	copy(msgBuffer, msg)

	return encMsg
}

// PKCS 1.5 Unpad (See RFC 3447 7.2.1 https://tools.ietf.org/html/rfc3447#section-7.2.1)
func Unpad(encMsg []byte) (msg []byte) {
	encMsgLen := len(encMsg)

	if encMsgLen < MinPaddingLen {
		jww.FATAL.Panicf("Could not remove padding: encoded message is less than min padding length")
	}

	// RFC 3447 7.2.1-2 defines the following padding format:
	// encMsg = 0x00 || 0x02 || paddingString || 0x00 || message

	// Check 1st padding octet
	if encMsg[0] != 0x00 {
		jww.FATAL.Panicf("Could not remove padding: padding prefix invalid because 1st octet of encoded message must be 0x00")
	}

	// Check 2nd padding octet
	if encMsg[1] != 0x02 {
		jww.FATAL.Panicf("Could not remove padding: padding prefix invalid because 2nd octet of encoded message must be 0x02")
	}

	// Check that the smallest possible padding string contains non-zero octets.
	minPaddingStr := encMsg[2:MinPaddingLen-1]
	for _, oct := range minPaddingStr {
		if oct == 0x00 {
			jww.FATAL.Panicf("Could not remove padding: min. sized padding string contains an octet with a value of zero")
		}
	}

	// Search for first zero octet after min. padding string and panic if not found.
	termInd := 0
	for i, oct := range encMsg[MinPaddingLen:] {
		if oct == 0x00 {
			jww.INFO.Printf("Found end of padding in encoded message at %v", termInd)
			termInd = i
			break
		}
	}
	if termInd == 0 {
		jww.FATAL.Panicf("Could not remove padding: unable to detect terminating octet index")
	}


	// Extract message after padding
	msg = encMsg[termInd+1:]
	msgLen := len(msg)

	// Check that message is not too long
	if msgLen > encMsgLen - MinPaddingLen {
		jww.FATAL.Panicf("Could not remove padding: message too long")
	}

	return msg

}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
// Function nonZeroRandomBytes taken from x/crypto/openpgp/elgamal/elgamal.go and crypto/rsa/pkcs1v15.go
// and modified to explicitly panic instead of return an error.
func nonZeroRandomBytes(s []byte, rand io.Reader) {
	// Fill slice with random octets (including zeros)
	_, err := io.ReadFull(rand, s)
	if err != nil {
		jww.FATAL.Panicf("Error readding full length of buffer from rand Reader into slice: %v", err.Error())
	}

	for i := 0; i < len(s); i++ {
		// If a zero octet was added to slice, loop until it is replaced with a non-zero octet
		for s[i] == 0 {
			_, err := io.ReadFull(rand, s[i:i+1])
			if err != nil {
				jww.FATAL.Panicf("Could not repolace zero octet with a non-zero octet: %v", err.Error())
			}
		}
	}
}
