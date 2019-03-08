////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package registration

import "testing"

func TestDssTypeDescriptor(t *testing.T) {
	var scheme Scheme = DSAScheme{}

	if scheme.SchemeMetadata() != "DSAScheme" {
		t.Errorf("Invalid Type Descriptor")
	}
}
