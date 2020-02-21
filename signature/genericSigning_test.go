////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

var testSig *TestSignable

func TestMain(m *testing.M) {
	// Arbitrary test values
	testId := []byte{1, 2, 3}
	testTime := uint32(4)
	testTopology := []string{"te", "st", "test"}
	testSize := uint64(42)
	// construct a TestSignable with arbitrary values
	testSig = &TestSignable{
		id:       testId,
		time:     testTime,
		topology: testTopology,
		size:     testSize,
	}

	m.Run()
}

// Happy path
func TestSign(t *testing.T) {

	Sign(testSig)

	// Serialize the data as testSig would
	testSigData := testSig.String()
	// Hash the data
	h := sha256.New()
	h.Write([]byte(testSigData))
	hashedData := h.Sum(nil)

	// Compare to the value of the signature
	if bytes.Compare(hashedData, testSig.signature) != 0 {
		t.Errorf("Test signature did not match: Expected: %+v \n\t"+
			"Receieved: %+v", testSig.signature, hashedData)
	}

}

// Error path
func TestSign_Error(t *testing.T) {
	// Sign object and fetch signature
	Sign(testSig)
	ourSign := testSig.GetSignature()

	// Input a random set of bytes
	randByte := make([]byte, len(ourSign))
	rand.Read(randByte)

	// Compare signature to random set of bytes (expected to not match)
	if bytes.Compare(ourSign, randByte) != 0 {
		return
	}

	t.Errorf("Expected error path: Should not have a matching random byte slice and signature")
}

// Happy path
func TestSignVerify(t *testing.T) {
	// Sign object and verify
	Sign(testSig)
	if !Verify(testSig) {
		t.Errorf("Expected happy path: Verification should not fail here!")
	}

}

// Error path
func TestSignVerify_Error(t *testing.T) {

	// Sign object
	Sign(testSig)

	// Modify object post-signing
	testSig.topology = []string{"fail", "fa", "il", "failfail"}

	// Attempt to verify modified object
	if !Verify(testSig) {
		return
	}
	t.Errorf("Expected error path: Verify should not return true")

}

// --------- Create mock Signable object ------------------

// Test struct with arbitrary fields to be signed and verified
type TestSignable struct {
	id        []byte
	time      uint32
	topology  []string
	size      uint64
	signature []byte
	nonce     []byte
}

func (ts *TestSignable) String() string {
	b := make([]byte, 0)

	// Append the id
	b = append(b, ts.id...)

	// Serialize the time
	a := make([]byte, 4)
	binary.LittleEndian.PutUint32(a, ts.time)
	b = append(b, a...)

	// Append the topology
	for _, val := range ts.topology {
		b = append(b, []byte(val)...)
	}

	// Append the size
	binary.PutUvarint(b, ts.size)

	return string(b)
}

func (ts *TestSignable) GetSignature() []byte {
	return ts.signature
}

func (ts *TestSignable) ClearSignature() {
	ts.signature = nil
}

func (ts *TestSignable) SetSignature(newSignature []byte) error {
	if newSignature == nil {
		return errors.New("Cannot set signature to nil value")
	}
	ts.signature = newSignature
	return nil
}

func (ts *TestSignable) GetNonce() []byte {
	return ts.nonce
}

func (ts *TestSignable) SetNonce(newNonce []byte) error {
	if newNonce == nil {
		return errors.New("Cannot set signature to nil value")
	}
	ts.nonce = newNonce
	return nil
}
