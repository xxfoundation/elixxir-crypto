////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"fmt"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/yawning/nyquist.git"
)

// panicOnNoiseError is a helper function which will panice for errors on the
// Noise protocol's Encrypt/Decrypt. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnNoiseError(hs *nyquist.HandshakeState, err error) {
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

// recoverErrorOnNoise is a helper function which will handle error on the
// Noise protocol's Encrypt/Decrypt. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func recoverErrorOnNoise(hs *nyquist.HandshakeState, err error) error {
	switch err {
	case nyquist.ErrDone:
		status := hs.GetStatus()
		if status.Err != nyquist.ErrDone {
			return status.Err
		}
	case nil:
	default:
		return err
	}
	return nil
}

// panicOnError is a helper function which will panic if the
// error is not nil. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnError(err error) {
	if err != nil {
		jww.FATAL.Panicf("%+v", err)
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

// panicOnChaChaFailure is a helper function which will panic if the
// error is not nil. This primarily serves as a fix for
// the coverage hit by un-testable error conditions.
func panicOnChaChaFailure(err error) {
	if err != nil {
		panic(fmt.Sprintf("Could not init XChaCha20Poly1305 mode: %s",
			err.Error()))
	}
}
