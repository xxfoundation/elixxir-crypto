////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
)

// Tests that a payload encrypted with Symmetric.Encrypt and decrypted with
// Symmetric.Decrypt matches the original.
func TestSymmetric_Encrypt_Decrypt(t *testing.T) {

	s, _, err := NewChannel("alice", "description", 528, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	payload := make([]byte, 256)
	rand.New(rand.NewSource(42)).Read(payload)

	packetSize := 1000

	encryptedPayload, mac, fp, err := s.EncryptSymmetric(payload, packetSize, csprng.NewSystemRNG())
	if err != nil {
		t.Errorf("Failed to enbcrypt payload: %+v", err)
	}

	decryptedPayload, err := s.DecryptSymmetric(encryptedPayload, mac, fp)
	if err != nil {
		t.Errorf("Failed to decrypt payload: %+v", err)
	}

	if !bytes.Equal(payload, decryptedPayload) {
		t.Errorf("Decrypted payload does not match original."+
			"\nexpected: %v\nreceived: %v", payload, decryptedPayload)
	}
}

// Tests that Symmetric.Decrypt returns an error when the MAC is invalid.
func TestSymmetric_Decrypt(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	s, _, err := NewChannel("alice", "description", 528, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	payload := make([]byte, 256)
	prng.Read(payload)

	packetSize := 1000

	encryptedPayload, mac, fp, err := s.EncryptSymmetric(payload, packetSize, csprng.NewSystemRNG())
	if err != nil {
		t.Errorf("Failed to enbcrypt payload: %+v", err)
	}

	// Create bad MAC
	prng.Read(mac)

	_, err = s.DecryptSymmetric(encryptedPayload, mac, fp)
	if err == nil || err.Error() != errVerifyMAC {
		t.Errorf("decyption should have failed with invalid MAC."+
			"\nexpected: %s\nreceived: %+v", errVerifyMAC, err)
	}
}

// Tests that a Symmetric marshalled by Symmetric.Marshal and unmarshalled via
// UnmarshalSymmetric matches the original.
func TestSymmetric_Marshal_UnmarshalSymmetric(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	pk, err := rsa.GetScheme().Generate(rng, 64)
	if err != nil {
		t.Fatalf("Failed to generate key: %+v", err)
	}
	pubKey := pk.Public()

	s := &Channel{
		ReceptionID:   id.NewIdFromString("ChannelID", id.User, t),
		Name:          "MyChannel",
		Description:   "Channel for channel stuff.",
		Salt:          cmix.NewSalt(csprng.Source(&csprng.SystemRNG{}), 32),
		RsaPubKeyHash: HashSecret(oldRsa.CreatePublicKeyPem(pubKey.GetOldRSA())),
	}

	data, err := s.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal Symmetric: %+v", err)
	}

	newSymmetric, err := UnmarshalChannel(data)
	if err != nil {
		t.Errorf("Failed to ummarshal Symmetric: %+v", err)
	}

	if !reflect.DeepEqual(s, newSymmetric) {
		t.Errorf("Marshalled and unmarshalled Symmetric does not match "+
			"original.\nexpected: %+v\nreceived: %+v", s, newSymmetric)
	}
}

// Tests consistency of NewSymmetricKey.
func TestNewSymmetricKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedKeys := []string{
		"YFcaO/zEULS9vMUstPJSGgcD+4rs+wRMmQwirYAf4TY=",
		"Kww9lMeLE5Ud+Z60Y3dL6rmbVbDYgGGoEjuetejAj6A=",
		"IDlVxZaxNr3VMBpxEC7fe2mF/H3+0HNdqbfd11wN84Y=",
		"sTsbdAAk9GNhAcHQo1f2DOBTKKVwbCPdKzujjSlcQag=",
		"2zWuXh4Cq8TPc1ffXJ05fT6POmeYcNOF9PuSmYFhA+E=",
		"e/xUE3UQKEVE85Z/AC2BfrwAGa9HVcZ3EacgSTZWF7s=",
		"7RzVqo2HHUySxAdp/s9FyNCWpZ/d8xXwnVTamr8o5hI=",
		"pfu9fs8TAALiuGB0qLCiWlkpMvvsKkSZRUPfoIwPq04=",
		"DKqeBhgZcCjB6izXjtSNjpC1JebEmwHhPKtMSSSID5g=",
		"4bfnVYIqKT1+JKbeRchmg7wTWbTV86IkQxc223lAD/c=",
	}

	secret := make([]byte, 32)

	for i, expected := range expectedKeys {

		n, err := prng.Read(secret)
		if err != nil {
			panic(err)
		}
		if n != 32 {
			panic("failed to read from rng")
		}

		key, err := NewSymmetricKey("alice",
			"chan description",
			[]byte("salt"),
			[]byte("my fake rsa key"),
			secret)
		if err != nil {
			panic(err)
		}

		keyStr := base64.StdEncoding.EncodeToString(key)

		if expected != keyStr {
			t.Errorf("Key does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, keyStr)
		}
	}
}

// Tests that changing the reception ID passed to NewSymmetricKey always results
// in a unique key.
func TestNewSymmetricKey_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const n = 100
	keys := make(map[string]bool, n)
	secret := make([]byte, 32)

	for i := 0; i < n; i++ {
		n, err := prng.Read(secret)
		if err != nil {
			panic(err)
		}
		if n != 32 {
			panic("failed to read from rng")
		}

		key, err := NewSymmetricKey("alice",
			"chan description",
			[]byte("salt"),
			[]byte("my fake rsa key"),
			secret)
		if err != nil {
			panic(err)
		}

		keyStr := base64.StdEncoding.EncodeToString(key)

		if keys[keyStr] {
			t.Errorf("Key already exists in map (%d)."+
				"\nkey: %v\n", i, key)
		} else {
			keys[keyStr] = true
		}
	}
}
