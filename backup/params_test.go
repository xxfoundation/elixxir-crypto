////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package backup

import (
	"reflect"
	"testing"
)

// Tests that a Params marshalled by Params.Marshal can be unmarshalled by
// Params.Unmarshal.
func TestParams_Marshal_Unmarshal(t *testing.T) {
	p := DefaultParams()

	marshalledBytes := p.Marshal()

	if len(marshalledBytes) != ParamsLen {
		t.Errorf("Length of marshalled Param bytes incorrect."+
			"\nexpected: %d\nreceived: %d", ParamsLen, len(marshalledBytes))
	}

	var newParams Params
	err := newParams.Unmarshal(marshalledBytes)
	if err != nil {
		t.Errorf("Unmarshal returned an error: %+v", err)
	}

	if !reflect.DeepEqual(p, newParams) {
		t.Errorf("Unmarshalled Params does not match original."+
			"\nexpected: %+v\nreceived: %+v", p, newParams)
	}
}
