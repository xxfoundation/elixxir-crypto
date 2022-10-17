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
	salt, err := hex.DecodeString("8a26d3c2edcaef6c9b401b5b0197505d897bf415b3f43c8016f4fc46db729873")
	require.NoError(t, err)
	hashedPubKey, err := hex.DecodeString("4ee999fc28e18b439c36f0ca20bebb178cb8a5115d394bcd8b767bca1e90309d")
	require.NoError(t, err)
	secret, err := hex.DecodeString("fec630412265ee468055455c8bf52dbcb40ae79eb3d243db1373383b8073ffcd")
	require.NoError(t, err)

	intermediary := deriveIntermediary(name, description, Public, salt, hashedPubKey, HashSecret(secret))
	wantIntermediary, err := hex.DecodeString("8bcc7ab97b1c7638067f93eb70369c1567ca3e58db65741135cd40acc068333c")
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

	rid, err := NewChannelID(
		name, description, Public, salt, hashedPubKey, HashSecret(secret))
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}

	wantID, err := hex.DecodeString("a49f37bfa37e02b28660519a32cdd749c4d7124364c12de2abb26dc4ea1725ef03")
	require.NoError(t, err)
	require.Equal(t, rid[:], wantID)
}

func TestChannel_deriveIntermediary(t *testing.T) {
	name := "mychannelname"
	description := "my channel description"
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

	intermediary := deriveIntermediary(name, description, Public, salt,
		HashPubKey(privateKey.Public()), HashSecret(secret))

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

	rid, err := NewChannelID(name, description, Public, salt,
		HashPubKey(privateKey.Public()), HashSecret(secret))
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}
}
