////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Consistency test of NewMessageID.
func TestNewMessageID_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedIDs := []string{
		"PPaNhdjaUzC15BA/q4Fu/fu6IpGgEZ5A1ZB9bbzfaZk=",
		"lDtpfSv/XQ0WLXH+utR0/q+SFFpm9tvcHVlRMpyKJY4=",
		"S+uvkGS3HWbzGct35RV9OopgveuqIJX8C4WYOyXgeTY=",
		"l6Qazvc7HjYvN2ZYAd6yGWqVyhi+fxcuDyI5KfglS/8=",
		"J05UrpmFPS+L5i4S7kBOcQ5vei0G8ad265TOh9UUFn0=",
		"g4BIMqW/somuJlFRAmvnDkjJ4x0+9GOwDFZZrNEt8E8=",
		"Kkjl1ibJkxacyMyWB6JvGcecWw+y7Y0PUw1WEQaymeo=",
		"Yv5mXavvznTX+kWIBEEsFcG7NvvCIFzRKUrfzOYM7zY=",
		"B44DgvvR2jMgqxxIsHImxqaFzQjC0wJuUsHpmzxb+Vw=",
		"RxKd81fKmxucALs+aOknJljvi2h1KPZxSIV3aFm30y4=",
	}

	for i, expected := range expectedIDs {
		gid := randID(prng, id.Group)
		internalFormat := make([]byte, 255)
		prng.Read(internalFormat)

		mid := NewMessageID(gid, internalFormat)
		midString := base64.StdEncoding.EncodeToString(mid[:])

		if expected != midString {
			t.Errorf("NewMessageID did not return the expected ID (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, midString)
		}

		// fmt.Printf("\"%s\",\n", midString)
	}
}

// Test that NewMessageID returns unique message IDs when the group ID and the
// internal message format are changed individually.
func TestNewMessageID_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	ids := map[string]bool{}
	gid := randID(prng, id.Group)
	internalFormat := make([]byte, 255)
	prng.Read(internalFormat)

	// Test changes to group ID
	for i := 0; i < 100; i++ {
		mid := NewMessageID(gid, internalFormat)
		midString := base64.StdEncoding.EncodeToString(mid[:])

		if ids[midString] {
			t.Errorf("Message ID %s already exists in the map (%d).", midString, i)
		} else {
			ids[midString] = true
		}

		gid = randID(prng, id.Group)
	}

	// Test changes to the internal message format
	for i := 0; i < 100; i++ {
		mid := NewMessageID(gid, internalFormat)
		midString := base64.StdEncoding.EncodeToString(mid[:])

		if ids[midString] {
			t.Errorf("Message ID %s already exists in the map (%d).", midString, i)
		} else {
			ids[midString] = true
		}

		prng.Read(internalFormat)
	}
}

// Happy path.
func TestMessageID_Bytes(t *testing.T) {
	expected := make([]byte, MessageIdLen)
	rand.New(rand.NewSource(42)).Read(expected)
	var mid MessageID
	copy(mid[:], expected)

	if !bytes.Equal(expected, mid.Bytes()) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, mid.Bytes())
	}
}

// Happy path.
func TestMessageID_String(t *testing.T) {
	buff := make([]byte, MessageIdLen)
	rand.New(rand.NewSource(42)).Read(buff)
	var mid MessageID
	copy(mid[:], buff)

	expected := base64.StdEncoding.EncodeToString(buff)

	if expected != mid.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, mid.String())
	}
}
