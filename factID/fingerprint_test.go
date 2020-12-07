///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package factID

import (
	"bytes"
	"fmt"
	"gitlab.com/elixxir/primitives/fact"
	"testing"
)

func TestFingerprint(t *testing.T) {
	expected := []byte("\xf0dD\u05fbb\xf6\x85\xde\xd9\x1a,\xaah\x85\xf0\xfchp\xf4\xd3\xc9[{\x87.\xe6e\xec\x18\xacI")
	testVal, err := fact.NewFact(fact.Email, "marie@elixxir.io")
	if err != nil {
		t.Fatal(err)
	}
	retVal := Fingerprint(testVal)
	if !bytes.Equal(retVal, expected) {
		fmt.Println(retVal)
		t.Errorf("Fingerprint failed, Expected: %+q, Got: %+q", expected, retVal)
	}
}
