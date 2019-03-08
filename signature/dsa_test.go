////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"testing"
)

func TestCustomDSAParams(t *testing.T) {

	var pVal, qVal, gVal int64 = 123, 234, 456

	p := cyclic.NewInt(pVal)
	q := cyclic.NewInt(qVal)
	g := cyclic.NewInt(gVal)

	dsaParams := CustomDSAParams(p, q, g)

	if dsaParams.params.P.Int64() != pVal {
		t.Errorf("p value doesn't match")
	}
	if dsaParams.params.Q.Int64() != qVal {
		t.Errorf("q value doesn't match")
	}
	if dsaParams.params.G.Int64() != gVal {
		t.Errorf("g value doesn't match")
	}


}
