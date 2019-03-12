package registration

import (
	"crypto/rand"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/signature"
	"testing"
)

// Test GenUserID normal operation with a randomly
// generated public key and a fixed salt
func TestGenUserID(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader, signature.L2048N256)
	pubKey := privKey.PublicKeyGen()
	salt := []byte("0123456789ABCDEF0123456789ABCDEF")

	user := GenUserID(pubKey, salt)
	if user == nil {
		t.Errorf("UserID Generation failed")
	}
}

// Test GenUserID panics with empty byte slice salt
func TestGenUserID_EmptySalt(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader, signature.L2048N256)
	pubKey := privKey.PublicKeyGen()
	salt := []byte("")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on empty salt")
		}
	}()
	GenUserID(pubKey, salt)
}

// Test GenUserID panics with nil salt
func TestGenUserID_NilSalt(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader, signature.L2048N256)
	pubKey := privKey.PublicKeyGen()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on nil salt")
		}
	}()
	GenUserID(pubKey, nil)
}

// Test GenUserID panics with empty byte slice public key
func TestGenUserID_EmptyKey(t *testing.T) {
	params := signature.NewDSAParams(rand.Reader, signature.L2048N256)
	privKey := params.PrivateKeyGen(rand.Reader, signature.L2048N256)
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

// Test GenUserID panics with nil public key
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

	tests := 100

	userMap := make(map[string]bool)


	for i := 0; i < tests; i++ {
		privKey := params.PrivateKeyGen(rand.Reader, signature.L2048N256)
		pubKey := privKey.PublicKeyGen()

		csprig := csprng.NewSystemRNG()
		salt := make([]byte, 32)
		csprig.Read(salt)


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
