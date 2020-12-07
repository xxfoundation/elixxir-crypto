/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package e2e

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

//tests io consistency of new message id
func TestNewMessageID_Consistency(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"iM34yCIr4Je8ZIzL9iAAG1UWAeDiHybxMTioMAaezvs=",
		"CWCzR/ODyGiS0q3ButzkWdgo6QNUz+/BscgIzNBSI68=",
		"4b6uZWMSn40DxCP3iviJGKY9ytjBY0ssxjCL9774EV0=",
		"D0UY/Yd/CzAbZHpBIBBtSkhnNCcJloxfPypF0ov+xVQ=",
	}

	for _, exp := range expected {
		rfp := make([]byte, 32)
		prng.Read(rfp)
		mid := NewMessageID(rfp, prng.Uint64())
		midString := base64.StdEncoding.EncodeToString(mid[:])
		if midString != exp {
			t.Errorf("Failed Message IDs are not consistant\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				midString)
		}
	}
}

// tests that all inputs impact the output
func TestNewMessageID_AllInputs(t *testing.T) {
	const NumCompares = 1000

	prng := rand.New(rand.NewSource(42))

	var fingerprints [][]byte
	var cIDs []uint64

	for i := 0; i < NumCompares; i++ {
		rfp := make([]byte, 32)
		prng.Read(rfp)
		fingerprints = append(fingerprints, rfp)
		cIDs = append(cIDs, prng.Uint64())
	}

	collisionMap := make(map[MessageID]struct{})

	for i := 0; i < NumCompares; i++ {
		for j := i + 1; j < NumCompares; j++ {
			mid := NewMessageID(fingerprints[i], cIDs[j])
			if _, ok := collisionMap[mid]; ok {
				t.Errorf("A message id collission ws found")
			}
			collisionMap[mid] = struct{}{}
		}
	}
}

//tests that the wrong size error triggers correctly
func TestUnmarshalMessageID_Error(t *testing.T) {
	nulMID := MessageID{}

	badMID, err := UnmarshalMessageID([]byte{69})
	if !bytes.Equal(badMID[:], nulMID[:]) {
		t.Errorf("Too small input did not return a nil message id")
	}

	if err == nil {
		t.Errorf("No error was returned with too small input")
	} else if !strings.Contains(err.Error(), "binary message ID is the "+
		"wrong length") {
		t.Errorf("wrong error returned when too small input: %s", err)
	}

	prng := rand.New(rand.NewSource(42))
	badBinary := make([]byte, 33)
	prng.Read(badBinary)

	badMID, err = UnmarshalMessageID(badBinary)
	if !bytes.Equal(badMID[:], nulMID[:]) {
		t.Errorf("Too small input did not return a nil message id")
	}

	if err == nil {
		t.Errorf("No error was returned with too small input")
	} else if !strings.Contains(err.Error(), "binary message ID is the "+
		"wrong length") {
		t.Errorf("wrong error returned when too small input: %s", err)
	}
}

//tests that unmarshal produces the correct result
func TestUnmarshalMessageID(t *testing.T) {

	expected := []string{
		"iM34yCIr4Je8ZIzL9iAAG1UWAeDiHybxMTioMAaezvs=",
		"CWCzR/ODyGiS0q3ButzkWdgo6QNUz+/BscgIzNBSI68=",
		"4b6uZWMSn40DxCP3iviJGKY9ytjBY0ssxjCL9774EV0=",
		"D0UY/Yd/CzAbZHpBIBBtSkhnNCcJloxfPypF0ov+xVQ=",
	}

	for _, exp := range expected {

		expectedInput, _ := base64.StdEncoding.DecodeString(exp)

		mid, err := UnmarshalMessageID(expectedInput)
		if err != nil {
			t.Errorf("unexpected rror returned on unmarshal: %s", err)
		}
		midString := base64.StdEncoding.EncodeToString(mid[:])
		if midString != exp {
			t.Errorf("Message IDs are not consistant\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				midString)
		}
	}
}

//tests that ths string function produces the correct truncated result
func TestMessageID_String_Consistency(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"iM34yCIr...",
		"CWCzR/OD...",
		"4b6uZWMS...",
		"D0UY/Yd/...",
	}

	for _, exp := range expected {

		rfp := make([]byte, 32)
		prng.Read(rfp)
		mid := NewMessageID(rfp, prng.Uint64())

		if mid.String() != exp {
			t.Errorf("Message ID string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				mid.String())
		}
	}
}

//tests that the string verbose produces the correct full result
func TestMessageID_StringVerbose_Consistency(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"iM34yCIr4Je8ZIzL9iAAG1UWAeDiHybxMTioMAaezvs=",
		"CWCzR/ODyGiS0q3ButzkWdgo6QNUz+/BscgIzNBSI68=",
		"4b6uZWMSn40DxCP3iviJGKY9ytjBY0ssxjCL9774EV0=",
		"D0UY/Yd/CzAbZHpBIBBtSkhnNCcJloxfPypF0ov+xVQ=",
	}

	for _, exp := range expected {

		rfp := make([]byte, 32)
		prng.Read(rfp)
		mid := NewMessageID(rfp, prng.Uint64())

		if mid.StringVerbose() != exp {
			t.Errorf("Message ID string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				mid.StringVerbose())
		}
	}
}

//tests that the string verbose produces the correct full result
func TestMessageID_Marshal_Consistency(t *testing.T) {

	prng := rand.New(rand.NewSource(42))

	expected := []string{
		"iM34yCIr4Je8ZIzL9iAAG1UWAeDiHybxMTioMAaezvs=",
		"CWCzR/ODyGiS0q3ButzkWdgo6QNUz+/BscgIzNBSI68=",
		"4b6uZWMSn40DxCP3iviJGKY9ytjBY0ssxjCL9774EV0=",
		"D0UY/Yd/CzAbZHpBIBBtSkhnNCcJloxfPypF0ov+xVQ=",
	}

	for _, exp := range expected {

		rfp := make([]byte, 32)
		prng.Read(rfp)
		mid := NewMessageID(rfp, prng.Uint64())

		if base64.StdEncoding.EncodeToString(mid.Marshal()) != exp {
			t.Errorf("Message ID string not as expected\n +"+
				"\tExpected: %s\n\tReceived: %s",
				exp,
				base64.StdEncoding.EncodeToString(mid.Marshal()))
		}
	}
}
