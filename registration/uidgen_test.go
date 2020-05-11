////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"crypto/rand"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"testing"
)

// Test GenUserID normal operation with a randomly
// generated public key and a fixed salt
func TestGenUserID(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Errorf("Could not generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()
	salt := []byte("0123456789ABCDEF0123456789ABCDEF")

	user := GenUserID(pubKey, salt)
	if user == nil {
		t.Errorf("UserID Generation failed")
	}
}

// Test GenUserID panics with empty byte slice salt
func TestGenUserID_EmptySalt(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Errorf("Could not generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()
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
	privKey, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Errorf("Could not generate private key: %+v", err)
	}
	pubKey := privKey.GetPublic()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("UserID Generation should panic on nil salt")
		}
	}()
	GenUserID(pubKey, nil)
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
	tests := 100

	userMap := make(map[string]bool)
	csprig := csprng.NewSystemRNG()

	for i := 0; i < tests; i++ {
		privKey, err := rsa.GenerateKey(rand.Reader, 768)
		if err != nil {
			t.Errorf("Could not generate private key: %+v", err)
		}
		pubKey := privKey.GetPublic()
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
