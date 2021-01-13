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

func ResponseKey(pubKey *cyclic.Int, keyNum uint64) []byte {
	return makeHash(pubKey, keyNum, responseKeyConstant)
}
