////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"bytes"
	"gitlab.com/xx_network/crypto/hash"
	"testing"
)

// Consistency test for CreateClientHMAC.
func TestCreateClientHMAC(t *testing.T) {
	expected := []byte{85, 5, 248, 79, 205, 253, 57, 75,
		103, 156, 80, 145, 94, 152, 74, 133, 29, 36,
		208, 143, 109, 214, 0, 4, 150, 124, 49, 88,
		168, 191, 178, 115}

	h, err := hash.NewCMixHash()
	if err != nil {
		t.Errorf("NewCMixHash failed: %v", err)
	}

	data := h.Sum([]byte("Hello, World!"))

	received := CreateClientHMAC(data, data, hash.DefaultHash)

	if !bytes.Equal(received, expected) {
		t.Errorf("Failed, expected: '%v', got: '%v'",
			expected, received)
	}

}

func TestVerifyClientHMAC(t *testing.T) {
	data := []byte("Hello, World!")

	if !VerifyClientHMAC(data, data, hash.DefaultHash,
		CreateClientHMAC(data, data, hash.DefaultHash)) {
		t.Fatalf("VerifyClientHMAC failed with same data")
	}

	badData := []byte("I am Iron Man")
	if VerifyClientHMAC(badData, badData, hash.DefaultHash,
		CreateClientHMAC(data, data, hash.DefaultHash)) {
		t.Fatalf("VerifyClientHMAC passed with differed data")
	}

}
