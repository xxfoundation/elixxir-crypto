///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
)

func TestTagVersion(t *testing.T) {
	blob := MarshalTagVersion()
	err := CheckMarshalledTagVersion(blob)
	require.NoError(t, err)
}

func TestStoreAndLoad(t *testing.T) {

	rsaPrivKey, err := rsa.GenerateKey(csprng.NewSystemRNG(), 4096)
	require.NoError(t, err)

	backup := &Backup{
		TransmissionIdentity: TransmissionIdentity{
			RSASigningPrivateKey: rsaPrivKey,
		},
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	ciphertext, err := backup.Marshal(csprng.NewSystemRNG(), key)
	require.NoError(t, err)

	newbackup := &Backup{}
	err = newbackup.Unmarshal(key, ciphertext)
	require.NoError(t, err)

	require.Equal(t, newbackup.TransmissionIdentity.RSASigningPrivateKey, backup.TransmissionIdentity.RSASigningPrivateKey)
}
