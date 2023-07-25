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
	"gitlab.com/xx_network/primitives/netTime"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"gitlab.com/xx_network/crypto/csprng"
)

// Tests that a payload encrypted with Symmetric.Encrypt and decrypted with
// Symmetric.Decrypt matches the original.
func TestSymmetric_Encrypt_Decrypt(t *testing.T) {

	s, _, err := NewChannel(
		"alice", "description", Public, 528, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	payload := make([]byte, 256)
	rand.New(rand.NewSource(42)).Read(payload)

	packetSize := 1000

	encryptedPayload, mac, fp, err := s.EncryptSymmetric(
		payload, packetSize, csprng.NewSystemRNG())
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

	s, _, err := NewChannel(
		"alice", "description", Public, 528, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	payload := make([]byte, 256)
	prng.Read(payload)

	packetSize := 1000

	encryptedPayload, mac, fp, err := s.EncryptSymmetric(
		payload, packetSize, csprng.NewSystemRNG())
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
	pk, err := rsa.GetScheme().Generate(rng, 256)
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
		"zxUn1z+TRg9h2fdT3KaSjFJ+InEQHWzO05ca8WfJwp8=",
		"OYfpbk5UjOi0z2XeUdC307QFj0zDbzT1Gd7oO9Z7h5I=",
		"ze7kOTK3vt7Qc7TB3/K4NolcNdMI8MMO3P4RJ/Mt/1I=",
		"37VKgKbKEGUsdqzH6p0/YoTTqdBzq8r+govftyYG+kY=",
		"06/tnqfhjxDwOjh6ObTSFNAtABH7R16/IQ3BHglzrhw=",
		"GfY+24Z+wxQwTaP81GdWveEy1mx8Whgo+uJGDF6CpNI=",
		"V+hwP/i22QtTTusIm+OYA8rmTC7R7+JLx/50qyQUHf8=",
		"Zuz+VwCn+AKuE9MQbXVe1zEKTKN9O5S3nq1u2o70A0I=",
		"4lSpoaxJIi+uwgZRcHeO9U3AhrZTwAFwrl+XWRD61Bo=",
		"JuGgFCYZJ9htuXQB5VlAm8jHp+6v3pZI9xTSjF7JaNY=",
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
			Public,
			time.Date(1955, 11, 5, 12, 0, 0, 0, time.UTC),
			i%2 == 0,
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
			Public,
			netTime.Now(),
			true,
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
