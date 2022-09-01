////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	"reflect"
	"testing"
)

// Quick unit test of Bogo.
func TestBogo(t *testing.T) {
	// original := []uint64{92, 79, 5, 63, 30, 53, 43, 71, 24, 56, 65, 54, 97, 81, 41, 45, 36, 28, 51, 90}
	// original := []uint64{92, 79, 5, 6, 30, 53, 43, 71, 24, 56}
	expected := []uint64{1, 2, 3}
	sorted := []uint64{3, 2, 1}
	n, dur := Bogo(sorted)
	t.Logf("Number of sorts: %d", n)
	t.Logf("Duration: %s", dur)

	if !reflect.DeepEqual(expected, sorted) {
		t.Errorf("Bogo() failed to sort the list."+
			"\nexpected: %v\nreceived: %v", expected, sorted)
	}
}
