////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"testing"
)

func TestPadErrorsOnLongMessage(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	encMsgLen := 20

	_, err := Pad(msg, encMsgLen)

	if err == nil {
		t.Errorf("Pad() failed, it must return an error when message it too large to be encoded")
	}
}

func TestPadDoesNotErrorOnValidMessage(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	encMsgLen := 32

	_, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}
}

func TestPadMaintainsMessageIntegrity(t *testing.T) {
	msg := []byte("0123456789ABCDEF")
	msgLen := len(msg)
	encMsgLen := 32

	encMsg, err := Pad(msg, encMsgLen)

	if err != nil {
		t.Errorf("Pad() failed, it must not error when encoding/padding a valid message")
	}

	// encMsgLen - msgLen - 1
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
	encMsgLen := 32

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
