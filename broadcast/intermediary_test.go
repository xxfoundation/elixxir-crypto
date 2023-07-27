package broadcast

import (
	"bytes"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/primitives/netTime"
	"hash"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
)

func TestChannel_deriveIntermediary_vector(t *testing.T) {
	name := "myChannelName"
	description := "my channel description"
	level := Public
	created := time.Date(1955, 11, 5, 12, 0, 0, 0, time.UTC)
	salt, err := hex.DecodeString(
		"8a26d3c2edcaef6c9b401b5b0197505d897bf415b3f43c8016f4fc46db729873")
	require.NoError(t, err)
	hashedPubKey, err := hex.DecodeString(
		"4ee999fc28e18b439c36f0ca20bebb178cb8a5115d394bcd8b767bca1e90309d")
	require.NoError(t, err)
	secret, err := hex.DecodeString(
		"8bcc7ab97b1c7638067f93eb70369c1567ca3e58db65741135cd40acc068333c")
	require.NoError(t, err)

	intermediary := deriveIntermediary(name, description, level, created,
		NewOptions(), salt, hashedPubKey, HashSecret(secret))
	wantIntermediary, err := hex.DecodeString(
		"9e80295813efd1bcdb19d1f236f53a4be249cbf1bdd402a7e9e85334d1ccf438")
	require.NoError(t, err)
	require.Equal(t, wantIntermediary, intermediary)

	hkdfHash := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
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

	rid, err := NewChannelID(name, description, level, created, NewOptions(),
		salt, hashedPubKey, HashSecret(secret))
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}

	wantID, err := hex.DecodeString(
		"7c736ca654836f784909facfd978e02c60a44771f6e43c9b8dce4b29fa3fb41603")
	require.NoError(t, err)
	require.Equal(t, rid[:], wantID)
}

func TestChannel_deriveIntermediary(t *testing.T) {
	name := "myChannelName"
	description := "my channel description"
	level := Public
	created := netTime.Now()
	rng := csprng.NewSystemRNG()
	salt := make([]byte, 32)
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

	intermediary := deriveIntermediary(name, description, level, created,
		NewOptions(), salt, HashPubKey(privateKey.Public()), HashSecret(secret))

	hkdfHash := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
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

	rid, err := NewChannelID(name, description, level, created, NewOptions(),
		salt, HashPubKey(privateKey.Public()), HashSecret(secret))
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}
}
