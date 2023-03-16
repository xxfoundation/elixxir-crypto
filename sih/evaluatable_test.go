////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package sih

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/primitives/id"
)

func TestCompressed(t *testing.T) {
	numSvcs := 10
	svcs := make([]evaluatableService, numSvcs)
	for i := 0; i < numSvcs; i++ {
		svcs[i] = &testEvSvc{
			tag: fmt.Sprintf("Tag: %d", i),
		}
	}

	lookFor := []evaluatableService{svcs[1], svcs[6]}

	pickup := &id.DummyUser
	msgHash := []byte("8675309 This IS a dummy messsage hash")

	sih, err := MakeCompessedSIH(pickup, msgHash, svcs)
	require.NoError(t, err)

	// SIH must be 200 bits, 25 bytes
	require.Equal(t, 25, len(sih))

	results, err := EvaluateCompessedSIH(pickup, msgHash, lookFor, sih)
	require.NoError(t, err)

	require.Equal(t, len(lookFor), len(results))
	for i := 0; i < len(lookFor); i++ {
		require.Contains(t, results, lookFor[i].Tag())
	}
}

type testEvSvc struct {
	tag string
}

func (t *testEvSvc) Hash(contents []byte) []byte {
	return nil
}

func (t *testEvSvc) Tag() string {
	return t.tag
}
