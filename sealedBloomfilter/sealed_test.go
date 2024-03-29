////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package bloomfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

// TestSealedInit creates, encrypts, and unseals an empty Sealed filter
func TestSealedInit(t *testing.T) {
	key := blake2b.Sum256([]byte("Hello World!"))
	nonce := blake2b.Sum256(key[:])

	orig, err := Init(key[:], nonce[:24], 30, 0.05, 2)
	require.NoError(t, err)
	unsealed, err := Init(key[:], nonce[:24], 30, 0.05, 2)
	require.NoError(t, err)

	// Test internal functionality as a smoke test.
	orgObj := orig.(*sealed)
	unsealedObj := unsealed.(*sealed)
	marsh, err := orgObj.filter.MarshalStorage()
	require.NoError(t, err)
	unsealedObj.filter.UnmarshalStorage(marsh)
	require.Equal(t, orgObj.filter, unsealedObj.filter)

	// Now check encryption
	metadata := []byte{42, 69}
	ciphertext, err := orig.Seal(metadata)
	require.NoError(t, err)
	recievedMetadata, err := unsealed.Unseal(ciphertext)
	require.NoError(t, err)
	require.Equal(t, orig, unsealed)
	require.Equal(t, metadata, recievedMetadata)
}

// TestSealedFuncs creates, adds, checks, encrypts, unseals, and
// checks again on a Sealed filter
func TestSealedFuncs(t *testing.T) {
	testVals := [][]byte{
		[]byte("How"),
		[]byte("Are"),
		[]byte("You"),
		[]byte("Doing"),
		[]byte("My"),
		[]byte("Friend"),
		[]byte("8675309"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	}
	key := blake2b.Sum256([]byte("Hello World!"))
	nonce := blake2b.Sum256(key[:])

	orig, err := InitByParameters(key[:], nonce[:24], 200, 10, 0)
	require.NoError(t, err)
	unsealed, err := InitByParameters(key[:], nonce[:24], 200, 10, 0)
	require.NoError(t, err)

	// Add a few values and Test
	for i := 0; i < len(testVals); i++ {
		orig.Add(testVals[i])
	}

	for i := 0; i < len(testVals); i++ {
		require.True(t, orig.Test(testVals[i]))
	}

	// Now check encryption
	ciphertext, err := orig.Seal(nil)
	require.NoError(t, err)
	// Note: 200/8 = 25
	require.Equal(t, 25, len(ciphertext))
	metadata, err := unsealed.Unseal(ciphertext)
	require.NoError(t, err)
	require.Equal(t, orig, unsealed)
	require.Equal(t, 0, len(metadata))
	// Other aspects
	require.Equal(t, 200, int(unsealed.GetSize()))
	require.Equal(t, orig.GetSize(), unsealed.GetSize())
	require.Equal(t, orig.GetHashOpCount(), unsealed.GetHashOpCount())

	for i := 0; i < len(testVals); i++ {
		require.True(t, unsealed.Test(testVals[i]))
	}

	// Reset and make sure we can't find anything
	orig.Reset()
	for i := 0; i < len(testVals); i++ {
		require.False(t, orig.Test(testVals[i]))
	}

}
