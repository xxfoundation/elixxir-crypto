////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// This file is only compiled for WebAssembly.

package rsa

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
)

// defaultRSABitLen is the RSA key length used in the system, in bits.
//
// WARNING: This bit size is smaller than the minimum recommended bit size of
//  3072. Do not use this in production. Only use it for testing.
//
// FIXME: Once WebAssembly can run in an HTTPS server, this should not be
//
//	necessary and needs to be removed. Do not use this is production.
var defaultRSABitLen = 1024

func init() {
	// Print with both jww and fmt to ensure that the message is seen
	msg := fmt.Sprintf("Using %d-bit RSA key size due to performance issues "+
		"with key generation in WebAssembly. This is not safe and not "+
		"generally compatible", defaultRSABitLen)
	fmt.Println(msg)
	jww.CRITICAL.Print(msg)
}
