////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"testing"

	"github.com/pkg/errors"
	"gitlab.com/yawning/nyquist.git"
)

func TestPanicOnError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	panicOnError(errors.Errorf("Test"))
	t.Errorf("did not panic")
}

func TestPanicOnRngFailure(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	panicOnRngFailure(0, 1)
	t.Errorf("did not panic")
}

func TestPanicOnChaChaFailure(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	panicOnChaChaFailure(errors.Errorf("Test"))
	t.Errorf("did not panic")
}

func TestPanicOnNoiseError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	cfg := &nyquist.HandshakeConfig{}
	hs, err := nyquist.NewHandshake(cfg)
	panicOnNoiseError(hs, err)
	t.Errorf("did not panic")
}

func TestRecoverOnNoiseError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	cfg := &nyquist.HandshakeConfig{}
	hs, err := nyquist.NewHandshake(cfg)
	recoverErrorOnNoise(hs, err)
	recoverErrorOnNoise(nil, err)
	t.Errorf("did not panic")
}
