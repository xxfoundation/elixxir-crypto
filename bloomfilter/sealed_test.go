////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
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

	orig, err := Init(key[:], nonce[:24], 30, 0.05)
	require.NoError(t, err)
	unsealed, err := Init(key[:], nonce[:24], 30, 0.05)
	require.NoError(t, err)

	// Test internal functionality as a smoke test.
	orgObj := orig.(*sealed)
	unsealedObj := unsealed.(*sealed)
	marsh, err := orgObj.filter.MarshalStorage()
	require.NoError(t, err)
	unsealedObj.filter.UnmarshalStorage(marsh)
	require.Equal(t, orgObj.filter, unsealedObj.filter)

	// Now check encryption
	ciphertext, err := orig.Seal()
	require.NoError(t, err)
	unsealed.Unseal(ciphertext)
	require.Equal(t, orig, unsealed)
}
