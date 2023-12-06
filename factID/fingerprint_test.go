////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package factID

import (
	"bytes"
	"fmt"
	"gitlab.com/elixxir/primitives/fact"
	"testing"
)

func TestFingerprint(t *testing.T) {
	expected := []byte("#\xdd\rC\xe0\u078f\u07a4j\xb4\xc36P\x85?\xfb\xe2dkRl\x06\x9fR1V\xe2\xf0\x94\u007f\r")
	testVal, err := fact.NewFact(fact.Email, "marie@elixxir.io")
	if err != nil {
		t.Fatal(err)
	}

	testVal2, err := fact.NewFact(fact.Email, "MARie@elixxir.io")
	if err != nil {
		t.Fatal(err)
	}

	retVal := Fingerprint(testVal)
	if !bytes.Equal(retVal, expected) {
		fmt.Println(retVal)
		t.Errorf("Fingerprint failed, Expected: %+q, Got: %+q", expected, retVal)
	}

	retVal2 := Fingerprint(testVal2)
	if !bytes.Equal(retVal2, retVal) {
		t.Errorf("Fingerprint case checking failed, first in [%+v] out [%+v], second in [%+v] out [%+v]",
			testVal.Fact, retVal, testVal2.Fact, retVal2)
	}
}
