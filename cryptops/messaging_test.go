////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import "testing"

// Compilation will fail if Keygen doesn't meet the interface
var _ Cryptop = Keygen

func TestKeygenPrototype_GetName(t *testing.T) {
	expected := "Keygen"
	if Keygen.GetName() != expected {
		t.Errorf("GetName didn't match. Expected %v, got %v", expected,
			Keygen.GetName())
	}
}

func TestKeygenPrototype_GetInputSize(t *testing.T) {
	expected := uint32(1)
	if Keygen.GetInputSize() != expected {
		t.Errorf("GetInputSize didn't match. Expected %v, got %v", expected,
			Keygen.GetInputSize())
	}
}
