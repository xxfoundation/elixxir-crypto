////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cryptops

import (
	"testing"
)

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
