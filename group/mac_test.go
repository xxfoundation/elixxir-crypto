////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"encoding/base64"
	"math/rand"
	"testing"
)

// Consistency test of NewMAC.
func TestNewMAC_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedMACs := []string{
		"ZhmxYgs565joaUDPAqTwaoGxT4sVrdbla8rGvfdbmlo=",
		"cz5qdjK4AnaVkxXTHNurMDBwEan0ngNnFNYIeDwaN74=",
		"SK141v83ahxHoGdLbSoEfLR81k3grUsc5HCWbebdF/0=",
		"csIMTmjxuunP9dm3YbG4+l0KsVfoIa0k5hjZKzEHNd0=",
		"VFyFNBHhGD8unpYwIXb00k6jsVnfhJY2oq+659n1jhw=",
		"TFXdUjisQ2SMmANoM/nx8ZXzjgee3G5UYpa8KJ72++s=",
		"W8edrqCRGcnVgVVzPguE4zWarJ7UMqofcwNsvah8mD0=",
		"NkcOGXJ95HOkq5okfgQ4h5VY4eCcDl2FPdFSPzhpLdw=",
		"WkFMHOaZ+kDTIBF3DKpjzXSgcNqMLxXHsnhMcKafqT4=",
		"aHmhf4l6IIntsbZW0fp2dq6nq2MWWjisBktHSMkhyRA=",
	}

	for i, expected := range expectedMACs {
		var key CryptKey
		prng.Read(key[:])
		encryptedInternalMsg := make([]byte, 255)
		prng.Read(encryptedInternalMsg)
		recipientDhKey := randCycInt(prng)

		mac := NewMAC(key, encryptedInternalMsg, recipientDhKey)
		macString := base64.StdEncoding.EncodeToString(mac)

		if expected != macString {
			t.Errorf("NewMAC did not return the expected MAC (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, macString)
		}

		// Ensure the first bit is zero
		if mac[0]>>7 != 0 {
			t.Errorf("NewMAC produced a MAC without the first bit being 0 (%d)."+
				"\nexpected: %d\nreceived: %d", i, 0, mac[0]>>7)
		}

		// fmt.Printf("\"%s\",\n", macString)
	}
}

// Test that NewMAC returns unique fingerprints when the key, encrypted internal
// message, and recipient DH key are changed individually.
func TestNewMAC_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	macs := map[string]bool{}
	var key CryptKey
	prng.Read(key[:])
	encryptedInternalMsg := make([]byte, 255)
	prng.Read(encryptedInternalMsg)
	recipientDhKey := randCycInt(prng)

	// Test changes to the key
	for i := 0; i < 100; i++ {
		mac := NewMAC(key, encryptedInternalMsg, recipientDhKey)
		macString := base64.StdEncoding.EncodeToString(mac)

		if macs[macString] {
			t.Errorf("MAC %s already exists in the map (%d).", macString, i)
		} else {
			macs[macString] = true
		}

		prng.Read(key[:])
	}

	// Test changes to the encrypted internal message
	for i := 0; i < 100; i++ {
		mac := NewMAC(key, encryptedInternalMsg, recipientDhKey)
		macString := base64.StdEncoding.EncodeToString(mac)

		if macs[macString] {
			t.Errorf("MAC %s already exists in the map (%d).", macString, i)
		} else {
			macs[macString] = true
		}

		prng.Read(encryptedInternalMsg)
	}

	// Test changes to the recipient DH key
	for i := 0; i < 100; i++ {
		mac := NewMAC(key, encryptedInternalMsg, recipientDhKey)
		macString := base64.StdEncoding.EncodeToString(mac)

		if macs[macString] {
			t.Errorf("MAC %s already exists in the map (%d).", macString, i)
		} else {
			macs[macString] = true
		}

		recipientDhKey = randCycInt(prng)
	}
}

// Unit test of CheckMAC.
func TestCheckMAC(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var key CryptKey
	prng.Read(key[:])
	encryptedInternalMsg := make([]byte, 255)
	prng.Read(encryptedInternalMsg)
	recipientDhKey := randCycInt(prng)

	mac := NewMAC(key, encryptedInternalMsg, recipientDhKey)

	check := CheckMAC(mac, key, encryptedInternalMsg, recipientDhKey)

	if !check {
		t.Error("CheckMAC failed to confirm the MAC.")
	}
}
