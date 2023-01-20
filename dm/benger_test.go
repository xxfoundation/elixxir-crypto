////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBenger(t *testing.T) {
	key := []byte("testkey")
	msg := []byte("testmsgs")

	bCode := makeBengerCode(key, msg)
	require.Equal(t, len(bCode), bengerCodeSize)

	require.True(t, isValidBengerCode(bCode, key, msg))

	require.False(t, isValidBengerCode([]byte("yo"), key, msg))
}
