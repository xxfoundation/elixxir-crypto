package registration

import (
	"crypto/rand"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/signature"
	"testing"
)

func TestGenUserID(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader)
	pubKey := privKey.PublicKeyGen()
	salt := []byte("0123456789ABCDEF0123456789ABCDEF")

	user := GenUserID(pubKey, salt)
	if user == nil {
		t.Errorf("UserID Generation failed")
	}
}

func TestGenUserID_EmptySalt(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader)
	pubKey := privKey.PublicKeyGen()
	salt := []byte("")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on empty salt")
		}
	}()
	GenUserID(pubKey, salt)
}

func TestGenUserID_NilSalt(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader)
	pubKey := privKey.PublicKeyGen()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on nil salt")
		}
	}()
	GenUserID(pubKey, nil)
}

func TestGenUserID_EmptyKey(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader)
	pubKey := privKey.PublicKeyGen()
	salt := []byte("0123456789ABCDEF0123456789ABCDEF")

	pubKey.GetKey().SetBytes([]byte(""))

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on empty key")
		}
	}()
	GenUserID(pubKey, salt)
}

func TestGenUserID_NilKey(t *testing.T) {
	salt := []byte("0123456789ABCDEF0123456789ABCDEF")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on nil key")
		}
	}()
	GenUserID(nil, salt)
}

func TestGenUserID_Random(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L1024N160)

	tests := 10000

	userMap := make(map[string]bool)

	for i := 0; i < tests; i++ {
		privKey := params.PrivateKeyGen(rand.Reader)
		pubKey := privKey.PublicKeyGen()
		salt, _ := cyclic.GenerateRandomBytes(32)
		user := GenUserID(pubKey, salt)
		if user == nil {
			t.Errorf("UserID Generation failed")
		} else {
			userMap[hex.EncodeToString(user.Bytes())] = true
		}
	}

	if len(userMap) < tests {
		t.Errorf("At least 2 out of %d UserIDs have the same value", tests)
	}
}
