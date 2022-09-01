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
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"testing"
)

// Tests that a payload encrypted with Symmetric.Encrypt and decrypted with
// Symmetric.Decrypt matches the original.
func TestSymmetric_Encrypt_Decrypt(t *testing.T) {
	s := &Channel{
		ReceptionID: id.NewIdFromString("channel", id.User, t),
	}

	payload := make([]byte, 256)
	rand.New(rand.NewSource(42)).Read(payload)

	encryptedPayload, mac, fp := s.EncryptSymmetric(payload, csprng.NewSystemRNG())

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
	s := &Channel{
		ReceptionID: id.NewIdFromString("channel", id.User, t),
	}

	payload := make([]byte, 256)
	prng.Read(payload)

	encryptedPayload, mac, fp := s.EncryptSymmetric(payload, csprng.NewSystemRNG())

	// Create bad MAC
	prng.Read(mac)

	_, err := s.DecryptSymmetric(encryptedPayload, mac, fp)
	if err == nil || err.Error() != errVerifyMAC {
		t.Errorf("decyption should have failed with invalid MAC."+
			"\nexpected: %s\nreceived: %+v", errVerifyMAC, err)
	}
}

// Tests that a Symmetric marshalled by Symmetric.Marshal and unmarshalled via
// UnmarshalSymmetric matches the original.
func TestSymmetric_Marshal_UnmarshalSymmetric(t *testing.T) {
	s := &Channel{
		ReceptionID: id.NewIdFromString("ChannelID", id.User, t),
		Name:        "MyChannel",
		Description: "Channel for channel stuff.",
		Salt:        cmix.NewSalt(csprng.Source(&csprng.SystemRNG{}), 32),
		RsaPubKey:   newRsaPubKey(rand.New(rand.NewSource(42)), t),
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
		"NyqSwQy3bb2S27QAkDW5bYF0WZ/KU/U8QncYICVuPU4=",
		"n/+Hppxdqdr0cDcytHpK/w1fPDjTWItf3JDOIVABQmQ=",
		"lAMHSlqviugCOykF43mFU0EIS0R1D6ul6bl/8Xu84So=",
		"ot/0LY7RPHj6yzqaIVpq+r/OoUdV8n+mqE8100SqLpE=",
		"qYHUQlAKVaHQaW8HFdloP1Y+pyTh1m18v/ouMS1pSNc=",
		"t7VgPknwXwwV8p2+j5FpGok7//DQkEelp/zCTa1u4c0=",
		"IXa4sR/wl5rRmrG4ocOE6vDmsy/TisBHITu8W1lbXBI=",
		"KWkrdtEPtBaaMQZtWmitu29zc3cH0omVyDrAf2X0u1U=",
		"1+diai0aKi7l/7O7QjjmdA5i7BmyqpRzvMo0/Rxouh8=",
		"5oONmqKbD6j8IdIBL62MKYmL57YjWXa+7zp/yTQydNg=",
	}

	for i, expected := range expectedKeys {
		receptionID, _ := id.NewRandomID(prng, id.User)

		key := NewSymmetricKey(receptionID)
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

	for i := 0; i < n; i++ {
		receptionID, _ := id.NewRandomID(prng, id.User)

		key := NewSymmetricKey(receptionID)
		keyStr := base64.StdEncoding.EncodeToString(key)

		if keys[keyStr] {
			t.Errorf("Key already exists in map (%d)."+
				"\nkey: %v\nreception ID: %s", i, key, receptionID)
		} else {
			keys[keyStr] = true
		}
	}
}
