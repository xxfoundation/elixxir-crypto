////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"syscall/js"
	"testing"
)

// Tests that subtleCrypto.callCatch catches the panic and returns it as an
// error.
func Test_subtleCrypto_callCatch(t *testing.T) {
	result, err := sc.callCatch("invalidMethod")
	if err == nil {
		t.Errorf("Expected error when calling a method on SubtleCrypto that " +
			"does not exist.")
	}
	if !result.IsUndefined() {
		t.Errorf("Result should be undefined.\nexpected: %v\nreceived: %v",
			js.Undefined(), result)
	}
}
