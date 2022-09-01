////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"golang.org/x/crypto/blake2b"
	"testing"
)

// Unit test of GenerateConnectionFingerprint.
func TestGenerateConnectionFingerprint(t *testing.T) {
	receiveFp := []byte{5}
	sendFp := []byte{10}
	h, _ := blake2b.New256(nil)
	h.Write(append(receiveFp, sendFp...))
	expected := h.Sum(nil)

	fp := GenerateConnectionFingerprint(sendFp, receiveFp)
	if !bytes.Equal(fp, expected) {
		t.Errorf("ConnectionFingerprint did not return the expected "+
			"fingerprint.\nexpected: %s\nreceived: %s", expected, fp)
	}

	// Flip the order and show that the output is the same.
	receiveFp, sendFp = sendFp, receiveFp

	fp = GenerateConnectionFingerprint(sendFp, receiveFp)
	if !bytes.Equal(fp, expected) {
		t.Errorf("ConnectionFingerprint did not return the expected "+
			"fingerprint.\nexpected: %s\nreceived: %s", expected, fp)
	}
}
