package broadcast

import (
	"bytes"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/rsa"
	"hash"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
)

func TestChannel_deriveIntermediary_vector(t *testing.T) {
	name := "mychannelname"
	description := "my channel description"
	salt, err := hex.DecodeString("3e8a29cc81cccb275f4353fe7a581a0717f871e39db015f3")
	require.NoError(t, err)
	hashedPubKey, err := hex.DecodeString("4ee999fc28e18b439c36f0ca20bebb178cb8a5115d394bcd8b767bca1e90309d")
	require.NoError(t, err)
	secret, err := hex.DecodeString("fec630412265ee468055455c8bf52dbcb40ae79eb3d243db1373383b8073ffcd")
	require.NoError(t, err)

	intermediary := deriveIntermediary(name, description, salt, hashedPubKey, HashSecret(secret))
	wantIntermediary, err := hex.DecodeString("a5300894d57215d6835c5cc41354e12a52cd1c4c186fb188a122a0e607adf188")
	require.NoError(t, err)
	require.Equal(t, wantIntermediary, intermediary)

	hkdfHash := func() hash.Hash {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	}

	hkdf1 := hkdf.New(hkdfHash, intermediary, salt, []byte(hkdfInfo))
	identityBytes := make([]byte, 32)
	_, err = io.ReadFull(hkdf1, identityBytes)
	if err != nil {
		panic(err)
	}
	sid := &id.ID{}
	copy(sid[:], identityBytes)
	sid.SetType(id.User)

	rid, err := NewChannelID(name, description, salt, hashedPubKey, secret)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}

	wantID, err := hex.DecodeString("e5c86b6798236ad8a22382e306d2d4da341c2a36caeab17f76d1f42ee46249c803")
	require.NoError(t, err)
	require.Equal(t, rid[:], wantID)
}

func TestChannel_deriveIntermediary(t *testing.T) {
	name := "mychannelname"
	description := "my channel description"
	rng := csprng.NewSystemRNG()
	salt := make([]byte, 24)
	_, err := rng.Read(salt)
	if err != nil {
		panic(err)
	}
	s := rsa.GetScheme()
	privateKey, err := s.Generate(rng, 4096)
	if err != nil {
		panic(err)
	}

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		panic(err)
	}

	intermediary := deriveIntermediary(name, description, salt, HashPubKey(privateKey.Public()), HashSecret(secret))

	hkdfHash := func() hash.Hash {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	}

	hkdf1 := hkdf.New(hkdfHash, intermediary, salt, []byte(hkdfInfo))
	identityBytes := make([]byte, 32)
	_, err = io.ReadFull(hkdf1, identityBytes)
	if err != nil {
		panic(err)
	}
	sid := &id.ID{}
	copy(sid[:], identityBytes)
	sid.SetType(id.User)

	rid, err := NewChannelID(name, description, salt, HashPubKey(privateKey.Public()), secret)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}
}
