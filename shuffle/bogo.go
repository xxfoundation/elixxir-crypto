////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	"time"
)

// Bogo is an implementations of bogosort using a Fisher-Yates shuffle. Returns
// the number of shuffles required to sort the list and the elapsed time.
func Bogo(slice []uint64) (int, time.Duration) {
	if len(slice) < 2 {
		return 0, 0
	}

	timeNow := time.Now()
	for i := 0; ; i++ {
		if isSorted(slice) {
			return i, time.Now().Sub(timeNow)
		}
		Shuffle(&slice)
	}
}

// isSorted determines if the list is sorted smallest to largest.
func isSorted(slice []uint64) bool {
	for i, item := range slice[1:] {
		if item < slice[i] {
			return false
		}
	}
	return true
}
