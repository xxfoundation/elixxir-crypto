///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"gitlab.com/elixxir/crypto/cyclic"
)

const responseKeyConstant = "responseKeyConstant"

// ResponseKey generates the key for the response message that corresponds with
// the given key number.
func ResponseKey(dhKey *cyclic.Int, keyNum uint64) []byte {
	return makeKeyHash(dhKey, keyNum, responseKeyConstant)
}
