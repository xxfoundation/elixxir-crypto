////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
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

	privKey := Edwards2ECDHNIKEPrivateKey(&edprivKey)
	pubDerived := ECDHNIKE.DerivePublicKey(privKey)

	pubConverted := Edwards2ECDHNIKEPublicKey(&edpubKey)

	require.Equal(t, pubDerived.Bytes(), pubConverted.Bytes())

	pubDownConverted := *ECDHNIKE2EdwardsPublicKey(pubConverted)

	require.Equal(t, edpubKey[:], pubDownConverted[:])
}
