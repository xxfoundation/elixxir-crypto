////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package factID

import (
	"bytes"
	"fmt"
	"git.xx.network/elixxir/primitives/fact"
	"testing"
)

func TestFingerprint(t *testing.T) {
	expected := []byte("\xdb\x10\x1e\xed\x0eAi\xb4\x13?[6\x0e\x154\xbd\x1a\xa8\x19\xb5\xaa\x1c\xfe\xb9\xd2\xe3\xfc\xfc\xa4\xbb\xd7\x01")
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
