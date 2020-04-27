////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	"crypto/rand"
	"errors"
	"fmt"
	"gitlab.com/elixxir/crypto/signature/rsa"
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

// Happy path / smoke test
func TestSign(t *testing.T) {
	// Generate keys
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()

	// Sign message
	err = Sign(testSig, privKey)
	if err != nil {
		t.Errorf("Failed to sign message: %+v", err)
	}

	// Check if the signature is valid
	if !rsa.IsValidSignature(pubKey, testSig.GetSig()) {
		t.Errorf("Failed smoke test! Signature is not at least as long as the signer's public key."+
			"\n\tSignature: %+v"+
			"\n\tSigner's public key: %+v", len(testSig.GetSig()), pubKey.Size())
	}
}

// Error path
func TestSign_Error(t *testing.T) {
	// Generate keys
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()

	// Sign object and fetch signature
	err = Sign(testSig, privKey)
	if err != nil {
		t.Errorf("Failed to sign: %+v", err)
	}
	ourSign := testSig.GetSig()

	// Input a random set of bytes less than the signature
	randByte := make([]byte, len(ourSign)/2)
	rand.Read(randByte)

	// Compare signature to random set of bytes (expected to not match)
	// Test arbitrary slice with server's public key
	if rsa.IsValidSignature(pubKey, randByte) {
		t.Errorf("Invalid signature returned valid! "+
			"\n\t Signature: %+v "+
			"\n\t Signer's public key: %+v", len(randByte), pubKey.Size())
	}
}

// Happy path
func TestSignVerify(t *testing.T) {
	// Generate keys
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()

	// Sign object
	err = Sign(testSig, privKey)
	if err != nil {
		t.Errorf("Failed to sign: +%v", err)
	}
	// Verify the signature
	err = Verify(testSig, pubKey)
	if err != nil {
		t.Errorf("Expected happy path! Verification resulted in: %+v", err)
	}

}

// Error path
func TestSignVerify_Error(t *testing.T) {
	// Generate keys
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()

	// Sign object
	Sign(testSig, privKey)

	// Modify object post-signing
	testSig.topology = []string{"fail", "fa", "il", "failfail"}
	testSig.nonce = []byte("i will fail")
	// Attempt to verify modified object
	err = Verify(testSig, pubKey)
	if err != nil {
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
	return fmt.Sprintf(
		"ID: %v\tTime: %v\tTopology: %v\tSize: %v\tNonce: %v\n",
		ts.id, ts.time, ts.topology, ts.size, ts.nonce)

}

func (ts *TestSignable) GetSig() []byte {
	return ts.signature
}

func (ts *TestSignable) ClearSig() {
	ts.signature = nil
}

func (ts *TestSignable) SetSig(newSignature []byte) error {
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
