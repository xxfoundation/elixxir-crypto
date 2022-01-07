////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"bytes"
	"gitlab.com/elixxir/crypto/hash"
	"testing"
)

// Consistency test for CreateClientHMAC.
func TestCreateClientHMAC(t *testing.T) {
	expected := []byte{209, 150, 187, 64, 160, 199, 29, 145, 153, 142, 9, 16,
		136, 3, 153, 120, 154, 199, 131, 163, 153, 213, 140, 135, 155, 220,
		15, 127, 247, 84, 125, 12}

	h, err := hash.NewCMixHash()
	if err != nil {
		t.Errorf("NewCMixHash failed: %v", err)
	}

	data := h.Sum([]byte("Hello, World!"))

	received := CreateClientHMAC(data, data, h)

	if !bytes.Equal(received, expected) {
		t.Errorf("Failed, expected: '%v', got: '%v'",
			expected, received)
	}

}

func TestVerifyClientHMAC(t *testing.T) {
	h, err := hash.NewCMixHash()
	if err != nil {
		t.Errorf("NewCMixHash failed: %v", err)
	}

	data := []byte("Hello, World!")

	if !VerifyClientHMAC(data, data, h, CreateClientHMAC(data, data, h)) {
		t.Fatalf("VerifyClientHMAC failed with same data")
	}

	badData := []byte("I am Iron Man")
	if VerifyClientHMAC(badData, badData, h, CreateClientHMAC(data, data, h)) {
		t.Fatalf("VerifyClientHMAC passed with differed data")
	}

}
