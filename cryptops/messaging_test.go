////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import "testing"

// Ensure that both cryptops implement the Cryptop interface
// Compilation will fail if they don't
var _ Cryptop = DecryptionKeygen
var _ Cryptop = EncryptionKeygen

func TestDecryptionKeygenPrototype_GetName(t *testing.T) {
	expected := "DecryptionKeygen"
	if DecryptionKeygen.GetName() != expected {
		t.Errorf("GetName didn't match. Expected %v, got %v", expected,
			DecryptionKeygen.GetName())
	}
}

func TestEncryptionKeygenPrototype_GetName(t *testing.T) {
	expected := "EncryptionKeygen"
	if EncryptionKeygen.GetName() != expected {
		t.Errorf("GetName didn't match. Expected %v, got %v", expected,
			EncryptionKeygen.GetName())
	}
}

func TestKeygenPrototype_GetInputSize(t *testing.T) {
	expected := uint32(1)
	if EncryptionKeygen.GetInputSize() != expected {
		t.Errorf("GetInputSize didn't match. Expected %v, got %v", expected,
			EncryptionKeygen.GetInputSize())
	}
	if DecryptionKeygen.GetInputSize() != expected {
		t.Errorf("GetInputSize didn't match. Expected %v, got %v", expected,
			DecryptionKeygen.GetInputSize())
	}
}
