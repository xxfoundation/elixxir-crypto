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

func TestChSmoke(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	inputs := make([][]byte, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs[i] = contents
		results[i] = DeriveChannelMessageID(chID, 8675309, contents)
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
