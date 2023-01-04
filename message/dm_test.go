////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/primitives/id"
)

func TestDMSmoke(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	inputs := make([][]byte, numTests)
	prng := rand.New(rand.NewSource(42))
	receptionID := &id.DummyUser

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs[i] = contents
		results[i] = DeriveDirectMessageID(receptionID,
			&dummyMsg{rndId: uint64(i)})
	}

	// Check the results are different
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				require.NotEqual(t, results[i], results[j])
			}
		}
	}
}

type dummyMsg struct {
	rndId uint64
}

func (d *dummyMsg) GetRoundID() uint64 {
	return d.rndId
}
func (d *dummyMsg) GetPayload() []byte {
	return []byte("Hi")
}
func (d *dummyMsg) GetPayloadType() uint32 {
	return 0
}
func (d *dummyMsg) GetNickname() string {
	return "Test"
}
func (d *dummyMsg) GetNonce() []byte {
	return []byte("Nonce")
}
func (d *dummyMsg) GetLocalTimestamp() int64 {
	return 8675309
}
