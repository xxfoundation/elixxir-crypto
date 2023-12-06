////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package hash

import (
	"encoding/hex"
	"testing"
)

// TestNewCMixHash tests that we get the expected value for the cmix hash
func TestNewCMixHash(t *testing.T) {
	expected := []byte{
		72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 14, 87, 81,
		192, 38, 229, 67, 178, 232, 171, 46, 176, 96, 153, 218, 161, 209, 229,
		223, 71, 119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168}
	h, err := NewCMixHash()
	if err != nil {
		t.Errorf("NewCMixHash failed: %v", err)
	}

	actual := h.Sum([]byte("Hello, World!"))

	for i, b := range actual {
		if b != expected[i] {
			t.Errorf("NewCMixHash byte %v failed, expected: '%v', got: '%v'",
				i, expected, actual)
		}
	}
}

// TestHMAC tests that we get the expected value for the payload "Mario" and a key "key"
func TestHMAC(t *testing.T) {
	payload := []byte("Mario")
	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")

	hmac1 := CreateHMAC(payload, key)
	expectedHMAC := "0b716229f4920f70265ee25045d3dc01f40ec423c4da97d249ca9c0dd146693e"

	if hex.EncodeToString(hmac1) != expectedHMAC {
		t.Errorf("TestHMAC(): Error 1: MACs should have matched!")
	}

	if !VerifyHMAC(payload, hmac1, key) {
		t.Errorf("TestHMAC(): Error 2: MACs should have matched!")
	}
}

// tests that the first bit is blanked when we have a leading 1 on
// the output
func TestHMAC_LeadingOne(t *testing.T) {
	payload := []byte("ARO00OOO")
	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")

	hmac1 := CreateHMAC(payload, key)

	if hmac1[0]>>7 != 0 {
		t.Errorf("First bit not blanked!")
	}
}
