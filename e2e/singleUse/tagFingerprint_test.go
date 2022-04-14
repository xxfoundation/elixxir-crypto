///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"testing"
)

// Tests that the generated tag fingerprint does not change.
func TestNewTagFP_Consistency(t *testing.T) {
	expectedFPs := []string{
		"m0cTfRUOrBSMCcsuDFubEA==",
		"n2wr2FhimigxeaKMQwoOww==",
		"gQFbF80cFWmRFJCKTcWAtg==",
		"6B330SPGBjmFIoBwkdkqhg==",
		"a+AuHpTbVLxbO/wNS6QPAg==",
		"Npgjn6oPpzAgDe2gb3VPHQ==",
		"vg0K64iRRVFdNs181ToEtg==",
		"w9LCSCCo76301pzLKGpvVQ==",
		"/7ZRLcScR6xlAkjPLHy3rg==",
		"yV37d2Zs0X+OJp9AlRWhjQ==",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedFP := range expectedFPs {
		tag := make([]byte, prng.Intn(255))
		prng.Read(tag)

		testFP := NewTagFP(string(tag))

		if expectedFP != testFP.String() {
			t.Errorf("NewTagFP did not return the expected fingerprint (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedFP, testFP)
		}
	}
}

// Tests that all generated tag fingerprints are unique.
func TestNewTagFP_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	FPs := make(map[TagFP]string)

	// Test with differing tag strings
	for i := 0; i < testRuns; i++ {
		tag := make([]byte, prng.Intn(255)+i)
		prng.Read(tag)
		testTagFP := NewTagFP(string(tag))

		if _, exists := FPs[testTagFP]; exists {
			t.Errorf("Generated tag fingerprint collides with previously "+
				"generated tag fingerprint (%d)."+
				"\ncurrent tag:   %s\npreviouse tag: %s\nFP:           %s",
				i, tag, FPs[testTagFP], testTagFP)
		} else {
			FPs[testTagFP] = string(tag)
		}
	}
}

// Happy path.
func TestUnmarshalTagFP(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fpBytes := make([]byte, TagFpSize)
	prng.Read(fpBytes)

	fp := UnmarshalTagFP(fpBytes)
	if !bytes.Equal(fpBytes, fp[:]) {
		t.Errorf("UnmarshalTagFP failed to copy the correct bytes into the "+
			"tag fingerprint.\nexpected: %+v\nreceived: %+v", fpBytes, fp)
	}

	// Ensure that the data is copied
	fpBytes[2]++
	if fp[2] == fpBytes[2] {
		t.Errorf("UnmarshalTagFP failed to create a copy of the data.")
	}
}

// Happy path.
func TestTagFP_Bytes(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fpBytes := make([]byte, TagFpSize)
	prng.Read(fpBytes)

	fp := UnmarshalTagFP(fpBytes)
	testFpBytes := fp.Bytes()
	if !bytes.Equal(fpBytes, testFpBytes) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %+v\nreceived: %+v", fpBytes, testFpBytes)
	}

	// Ensure that the data is copied
	testFpBytes[2]++
	if fp[2] == testFpBytes[2] {
		t.Errorf("Bytes failed to create a copy of the data.")
	}
}

// Happy path.
func TestTagFP_String(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fpBytes := make([]byte, TagFpSize)
	prng.Read(fpBytes)
	fp := UnmarshalTagFP(fpBytes)

	expectedString := base64.StdEncoding.EncodeToString(fpBytes)
	if expectedString != fp.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expectedString, fp.String())
	}
}
