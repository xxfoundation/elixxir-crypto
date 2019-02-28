////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestPadErrorsOnLongMessage(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	encMsgLen := len(msg) + 4

	_, err := Pad(msg, encMsgLen)

	if err == nil {
		t.Errorf("Pad() failed, it must return an error when message it too large to be encoded")
	}
}

func TestPadDoesNotErrorOnValidMessage(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	encMsgLen := len(msg) + 16

	_, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}
}

func TestPadMaintainsMessageIntegrity(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	msgLen := len(msg)
	encMsgLen := len(msg) + 16

	encMsg, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}

	containedMsg := encMsg[(encMsgLen - msgLen):]

	if !bytes.Equal(msg, containedMsg) {
		t.Errorf("Pad() failed, it did not maintain message integrity")
	}

}

func TestPaddingStringPrefixIsValid(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	encMsgLen := 32

	encMsg, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}

	if encMsg[0] != 0x00 {
		t.Errorf("Pad() failed, the first byte of padding should be 0x00")
	}

	if encMsg[1] != 0x02 {
		t.Errorf("Pad() failed, the second byte of padding should be 0x02")
	}
}

func TestPaddingStringTerminationIsValid(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	msgLen := len(msg)
	encMsgLen := msgLen+16

	encMsg, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}

	terminationIndex := encMsgLen - msgLen - 1

	if encMsg[terminationIndex] != 0x00 {
		t.Errorf("Pad() failed, the last byte of padding should be 0x00")
	}
}

func TestPaddingStringIsNonZero(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	msgLen := len(msg)
	encMsgLen := 32

	encMsg, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}

	terminationIndex := encMsgLen - msgLen - 1

	for _, num := range encMsg[2:terminationIndex] {
		if uint8(num) == 0 {
			t.Errorf("Pad() failed, the padding string must contain only non-zero values!")
		}
	}
}

func TestPaddingStringNotTheSame(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	msgLen := len(msg)

	// Large message size makes it highly improbable to get equal pads
	encMsgLen := msgLen + 512

	// Pad twice with same length
	encMsg1, err1 := Pad(msg, encMsgLen)
	encMsg2, err2 := Pad(msg, encMsgLen)

	if err1 != nil || err2 != nil {
		t.Error("Unable to pad a valid message")
	}

	if bytes.Equal(encMsg1, encMsg2) {
		t.Errorf("Padding string generated should not be the same")
	}
}

// TODO: Add different different rngs
func TestNonZeroRandomBytesAlwaysGenNonZeroByte(t *testing.T) {
	paddingLen := 384
	singleZero := []byte{0x00}
	iterations := 1000

	for i:=0; i<iterations; i++ {
		s := make([]byte, paddingLen)
		nonZeroRandomBytes(s, rand.Reader)

		if bytes.Contains(s, singleZero) {
			t.Errorf("nonZeroRandomBytes failed in setting a byte to zero")
		}
	}
}

type AlwaysErrorReader struct{}

func (r *AlwaysErrorReader) Read(b []byte) (int, error) {
	return 1, errors.New("external system error")
}

func TestNonZeroRandomBytesPanicsOnImmediateReaderError(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nonZeroRandomBytes should panic on reader error!")
		}
	}()

	paddingLen := 384
	s := make([]byte, paddingLen)
	r := AlwaysErrorReader{}

	nonZeroRandomBytes(s, &r)
}

func TestUnpadSmallEncodedMsg(t *testing.T) {
	encMsg := []byte("toosmall")

	_, err := Unpad(encMsg)

	if len(encMsg) >= MinPaddingLen {
		t.Errorf("This message exceeds the minimium pad len so test cannot proceed")
	}

	if err == nil {
		t.Errorf("Small encoded message (less than min size) should return an error")
	}
}

func TestUnpadEncodedMsgPrefix(t *testing.T) {
	validPrefix := []byte{0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01}
	invalidPrefix1 := []byte{0xAB, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01}
	invalidPrefix2 := []byte{0x00, 0xAB, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01}
	invalidPrefix3 := []byte{0xCD, 0xAB, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01}

	_, err := Unpad(validPrefix)

	if err != nil {
		t.Errorf("Valid prefix returned an error on unpad")
	}

	_, err = Unpad(invalidPrefix1)

	if err == nil {
		t.Errorf("Invalid prefix did not return an error on unpad")
	}

	_, err = Unpad(invalidPrefix2)

	if err == nil {
		t.Errorf("Invalid prefix did not return an error on unpad")
	}

	_, err = Unpad(invalidPrefix3)

	if err == nil {
		t.Errorf("Invalid prefix did not return an error on unpad")
	}
}
