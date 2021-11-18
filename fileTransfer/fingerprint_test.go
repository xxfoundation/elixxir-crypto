////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"testing"
)

// Consistency test: tests that GenerateFingerprint returns the expected
// fingerprints. If the expected values no longer match, then some underlying
// dependency has made a potentially breaking change.
func TestGenerateFingerprint(t *testing.T) {
	expectedFingerprints := []string{
		"IkCTKHqqcYBUwbxXIIZsXy5c59csaRXaoJiRsKuvaV4=",
		"ZKxZgntTMGKEOQHiAtYuEDV7hRFXFri3KMpmgYJubq8=",
		"deaLnzBQPp+r+6E8wVq6h0eMbhzkKVU56Ws9FWUttWw=",
		"IdEZrKUyxU1TKBIZom7Uu6Idejk1bah6+pyvxnVBCAo=",
	}

	prng := NewPrng(42)

	transferKey, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Could not generate transfer key: %+v", err)
	}

	for i, expected := range expectedFingerprints {
		fp := GenerateFingerprint(transferKey, uint16(i))
		if fp.String() != expected {
			t.Errorf("New fingerprint #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, fp)
		}

		// Ensure the first bit is zero
		if fp[0]>>7 != 0 {
			t.Errorf("First bit of fingerprint #%d is not 0."+
				"\nexpected: %d\nreceived: %d", i, 0, fp[0]>>7)
		}
	}

}

// Consistency test: tests that GenerateFingerprints returns the expected
// values. If the expected values no longer match, then some underlying
// dependency has made a potentially breaking change.
func TestGenerateFingerprints(t *testing.T) {
	testSegLen := 10
	prng := NewPrng(42)
	transferKey, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Could not generate transfer key: %+v", err)
	}

	testFingerprints := GenerateFingerprints(transferKey, uint16(testSegLen))
	if len(testFingerprints) != testSegLen {
		t.Fatalf("Unexpected number of fingerprints returned."+
			"\nexpected: %d\nreceived: %d", testSegLen, len(testFingerprints))
	}

	// Check that output is expected
	expected := []string{
		"IkCTKHqqcYBUwbxXIIZsXy5c59csaRXaoJiRsKuvaV4=",
		"ZKxZgntTMGKEOQHiAtYuEDV7hRFXFri3KMpmgYJubq8=",
		"deaLnzBQPp+r+6E8wVq6h0eMbhzkKVU56Ws9FWUttWw=",
		"IdEZrKUyxU1TKBIZom7Uu6Idejk1bah6+pyvxnVBCAo=",
		"d+GUR0bn5MGS8vOEyKCGaI8mRGLF/omHSRWOl1Oh+P4=",
		"RhSyK4/n56ifltW3yFCXxDW7oVQ/CiyNdRPbr0H9Wv4=",
		"dyIwjbz7vmf0KuNA9TZBKpnEIVg0iV97xq6Wpq8hi38=",
		"WJNdTbfNiv+gweEdGXsuvzzByei0DiRPSieqPCoW5Lc=",
		"EE3nTO2Yri46jcd1Ij3ng9c/0wGuopkL+Tj60GxEXhQ=",
		"MUHTCQkklaPxr1mAkuF4KJjA4ioefdjz5uCmhmOhnsA=",
	}

	for i, fp := range testFingerprints {
		if fp.String() != expected[i] {
			t.Errorf("Received fingerprint #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected[i], fp)
		}

		// Ensure the first bit is zero
		if fp[0]>>7 != 0 {
			t.Errorf("First bit of fingerprint #%d is not 0."+
				"\nexpected: %d\nreceived: %d", i, 0, fp[0]>>7)
		}
	}
}
