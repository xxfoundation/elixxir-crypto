////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEdwardsUtils(t *testing.T) {
	edpubKey, edprivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKey := Edwards2EcdhNikePrivateKey(edprivKey)
	pubDerived := ECDHNIKE.DerivePublicKey(privKey)

	pubConverted := Edwards2EcdhNikePublicKey(edpubKey)

	require.Equal(t, pubDerived.Bytes(), pubConverted.Bytes())

	pubDownConverted := EcdhNike2EdwardsPublicKey(pubConverted)

	require.Equal(t, edpubKey[:], pubDownConverted[:])
}
