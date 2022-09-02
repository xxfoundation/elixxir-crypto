package broadcast

import (
	"bytes"
	"hash"
	"io"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
)

func TestChannel_deriveIntermediary(t *testing.T) {
	name := "mychannelname"
	description := "my channel description"
	rng := csprng.NewSystemRNG()
	salt := make([]byte, 24)
	_, err := rng.Read(salt)
	if err != nil {
		panic(err)
	}

	privateKey, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		panic(err)
	}

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		panic(err)
	}

	intermediary := deriveIntermediary(name, description, salt, privateKey.GetPublic().GetN().Bytes(), secret)

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

	rid, err := NewChannelID(name, description, salt, privateKey.GetPublic().GetN().Bytes(), secret)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(rid[:], sid[:]) {
		t.Fatal()
	}
}
