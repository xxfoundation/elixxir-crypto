////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/yawning/nyquist.git"
)

// handleErrorOnNoise is a helper function which will handle error on the
// Noise protocol's Encrypt/Decrypt. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func handleErrorOnNoise(hs *nyquist.HandshakeState, err error) {
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			jww.FATAL.Panic(status.Err)
		}
	case nil:
	default:
		jww.FATAL.Panic(err)
	}

}

// panicOnError is a helper function which will panic if the
// error is not nil. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnError(err error) {
	if err != nil {
		jww.FATAL.Panic(err)
	}
}

// panicOnRngFailure is a helper function which will panic if the
// rng count is not of the expected size. This primarily serves as
// a fix for the coverage hit by un-testable error conditions.
func panicOnRngFailure(expected, received int) {
	if expected != received {
		jww.FATAL.Panic("rng failure")
	}
}
