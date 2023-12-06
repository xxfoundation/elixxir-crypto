////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
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
	identifier := []byte("MyIdentifier")
	numTags := 10
	tags := make([]string, numTags)
	for i := 0; i < numTags; i++ {
		tags[i] = fmt.Sprintf("Tag: %d", i)
	}

	lookFor := []string{tags[1], tags[6]}

	pickup := &id.DummyUser
	msgHash := []byte("8675309 This IS a dummy message hash")
	metaData := []byte{1, 2}
	sih, err := MakeCompressedSIH(pickup, msgHash, identifier, tags, metaData)
	require.NoError(t, err)

	// SIH must be 200 bits, 25 bytes
	require.Equal(t, 25, len(sih))

	matchedTags, receivedMetadata, identifierFound, err :=
		EvaluateCompressedSIH(pickup, msgHash, identifier, lookFor, sih)
	require.True(t, identifierFound)
	require.NoError(t, err)
	require.Equal(t, metaData, receivedMetadata)

	require.Equal(t, len(lookFor), len(matchedTags))
	for i := 0; i < len(lookFor); i++ {
		require.Contains(t, matchedTags, lookFor[i])
	}

	// Make sure it doesn't work when the identifier is wrong
	badIdentifier := []byte("BadIdentifier")
	matchedTags, receivedMetadata, identifierFound, err =
		EvaluateCompressedSIH(pickup, msgHash, badIdentifier, lookFor, sih)
	require.False(t, identifierFound)
	require.NoError(t, err)

	require.Equal(t, 0, len(matchedTags))
	require.Equal(t, 0, len(receivedMetadata))
}
