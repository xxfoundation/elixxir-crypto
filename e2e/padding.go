package e2e

import (
	"errors"
	"io"
	//"crypto/internal/randutil"
)

func Pad(msg []byte, encMsgLen int) (encMsg []byte, err error) {
	//randutil.MaybeReadByte(rand)

	return pad(nil, msg, encMsgLen)
}

// Impl. of PKCS 1.5 random non-zero padding as defined in RFC 3447 7.2.1
// See https://tools.ietf.org/html/rfc3447#section-7.2.1
func pad(rand io.Reader, msg []byte, encMsgLen int) (encMsg []byte, err error) {
	msgLen := len(msg)

	if msgLen > (encMsgLen - 11) {
		err = errors.New("message too long")
		return
	}

	encMsg = make([]byte, encMsgLen)

	// RFC 3447 7.2.1.2 defines the following padding format:
	// encMsg = 0x00 || 0x02 || padding || 0x00 || message
	encMsg[0] = 0x00
	encMsg[1] = 0x02

	padding := encMsg[2:(encMsgLen - msgLen - 1)]
	err = nonZeroRandomBytes(padding, rand)
	if err != nil {
		return nil, err
	}

	encMsg[encMsgLen - msgLen - 1] = 0x00

	msgBuffer := encMsg[encMsgLen - msgLen:]

	// Copy message into the end of encoded message buffer
	copy(msgBuffer, msg)

	return encMsg, nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
		}
	}

	return
}