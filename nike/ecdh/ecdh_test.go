////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ecdh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/crypto/csprng"
)

func TestFromEdwards(t *testing.T) {
	edpubKey, edprivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	alicePrivateKey := ECDHNIKE.NewEmptyPrivateKey()
	alicePublicKey := ECDHNIKE.NewEmptyPublicKey()

	alicePrivateKey.(*PrivateKey).FromEdwards(edprivKey)
	alicePublicKey.(*PublicKey).FromEdwards(edpubKey)

	rng := csprng.NewSystemRNG()

	bobPrivateKey, bobPublicKey := ECDHNIKE.NewKeypair(rng)

	secret1 := alicePrivateKey.DeriveSecret(bobPublicKey)
	secret2 := bobPrivateKey.DeriveSecret(alicePublicKey)

	require.Equal(t, secret1, secret2)
}

func TestNike(t *testing.T) {

	rng := csprng.NewSystemRNG()
	alicePrivateKey, alicePublicKey := ECDHNIKE.NewKeypair(rng)
	bobPrivateKey, bobPublicKey := ECDHNIKE.NewKeypair(rng)

	secret1 := alicePrivateKey.DeriveSecret(bobPublicKey)
	secret2 := bobPrivateKey.DeriveSecret(alicePublicKey)

	require.Equal(t, secret1, secret2)
}

func TestPrivateKeyMarshaling(t *testing.T) {
	rng := csprng.NewSystemRNG()
	alicePrivateKey, _ := ECDHNIKE.NewKeypair(rng)

	alicePrivateKeyBytes := alicePrivateKey.Bytes()
	alice2PrivateKey, _ := ECDHNIKE.NewKeypair(rng)

	err := alice2PrivateKey.FromBytes(alicePrivateKeyBytes)
	require.NoError(t, err)

	alice2PrivateKeyBytes := alice2PrivateKey.Bytes()

	require.Equal(t, alice2PrivateKeyBytes, alicePrivateKeyBytes)

	alice3PrivateKey, err := ECDHNIKE.UnmarshalBinaryPrivateKey(alice2PrivateKeyBytes)
	require.NoError(t, err)

	alice3PrivateKeyBytes := alice3PrivateKey.Bytes()

	require.Equal(t, alice3PrivateKeyBytes, alice2PrivateKeyBytes)
	require.Equal(t, len(alice3PrivateKeyBytes), ECDHNIKE.PrivateKeySize())
}

func TestPublicKeyMarshaling(t *testing.T) {
	rng := csprng.NewSystemRNG()

	_, alicePublicKey := ECDHNIKE.NewKeypair(rng)

	alicePublicKeyBytes := alicePublicKey.Bytes()
	_, alice2PublicKey := ECDHNIKE.NewKeypair(rng)

	err := alice2PublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	alice2PublicKeyBytes := alice2PublicKey.Bytes()

	require.Equal(t, alice2PublicKeyBytes, alicePublicKeyBytes)

	alice3PublicKey, err := ECDHNIKE.UnmarshalBinaryPublicKey(alice2PublicKeyBytes)
	require.NoError(t, err)

	alice3PublicKeyBytes := alice3PublicKey.Bytes()

	require.Equal(t, alice3PublicKeyBytes, alice2PublicKeyBytes)
	require.Equal(t, len(alice3PublicKeyBytes), ECDHNIKE.PublicKeySize())
}

func TestPrivateKey_Reset(t *testing.T) {
	rng := csprng.NewSystemRNG()
	alicePrivateKey, _ := ECDHNIKE.NewKeypair(rng)

	alicePrivateKey.Reset()

	privKeyBytes := alicePrivateKey.Bytes()
	expected := make([]byte, len(privKeyBytes))

	if !bytes.Equal(expected, privKeyBytes) {
		t.Fatalf("Failed to reset key, byte data is not all zeroes.")
	}
}

func TestPublicKey_Reset(t *testing.T) {
	rng := csprng.NewSystemRNG()
	_, alicePublicKey := ECDHNIKE.NewKeypair(rng)

	alicePublicKey.Reset()

	pubKeyBytes := alicePublicKey.Bytes()
	expected := make([]byte, len(pubKeyBytes))

	if !bytes.Equal(expected, pubKeyBytes) {
		t.Fatalf("Failed to reset key, byte data is not all zeroes.")
	}

}

func TestPrivateKey_Scheme(t *testing.T) {
	rng := csprng.NewSystemRNG()
	alicePrivKey, _ := ECDHNIKE.NewKeypair(rng)

	if !reflect.DeepEqual(alicePrivKey.Scheme(), ECDHNIKE) {
		t.Fatalf("GetScheme failed to retrieve expected value")

	}
}

func TestPublicKey_Scheme(t *testing.T) {
	rng := csprng.NewSystemRNG()
	_, alicePubKey := ECDHNIKE.NewKeypair(rng)

	if !reflect.DeepEqual(alicePubKey.Scheme(), ECDHNIKE) {
		t.Fatalf("GetScheme failed to retrieve expected value")

	}

}

func TestDerivePublicKey(t *testing.T) {
	rng := csprng.NewSystemRNG()
	alicePrivKey, alicePubKey := ECDHNIKE.NewKeypair(rng)

	pubKeyDerived := ECDHNIKE.DerivePublicKey(alicePrivKey)

	require.Equal(t, alicePubKey.Bytes(), pubKeyDerived.Bytes())

}
