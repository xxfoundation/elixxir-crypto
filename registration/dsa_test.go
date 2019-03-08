////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package registration

import "testing"

func TestDSATypeDescriptor(t *testing.T) {
	var scheme Scheme = DSAScheme{}

	if scheme.SchemeMetadata() != "DSAScheme" {
		t.Errorf("Invalid Type Descriptor")
	}
}

func TestDSAGobEncodeDecode(t *testing.T) {
	var scheme Scheme = DSAScheme{}



	b, e := scheme.GobEncode()

	if e != nil {
		t.Error("Failed to encode on DSA Encoder")
	}

	e = scheme.GobDecode(b)

	if e != nil {
		t.Errorf("Failed to decode")
	}
}