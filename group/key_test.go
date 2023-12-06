////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"testing"
	"time"
)

// Consistency test of NewKdfKey.
func TestNewKdfKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	keys := []string{
		"adNOdUSsMaK1UmOzrlTFsred4+V8yQcw8c8PRILMVvU=",
		"IBk2PbejkC9NP8EeG6fzpcBI00na63239xF3PPAjlTg=",
		"N3npiSdWJWlhzVZNg0bss3OJOb2emqYyguvPKyuy2nM=",
		"NS4gxkeEhn3a5u1qZD4WZnBf+ZwFrTod0NKN3iNyjA0=",
		"EUUrIimcS7OtiCsKFVA2jKPTtxdTcKjSkFBzBOFBBGQ=",
		"Hnzm+oZmG2vEzUzezLxVHClrhQfjVj6lvA8yVKwdSKQ=",
		"/4XoPF2Kqx8bMjebkwTznvyJJm/ECKeQDZuhOy23Mq8=",
		"vw+NS8hE96WBsAdo8FgWZmFDc4fzP+4+0XLevcBItYE=",
		"8uE9JECj/kxlUkAih/y2TvJ8Qt16jwIMhvxGX7OL7hY=",
		"MnaDCAAoR2oQjaOtrXQRxLiAJEHB/lFZJNey04/lS9M=",
	}

	for i, expected := range keys {
		var groupKey Key
		prng.Read(groupKey[:])
		var salt [SaltLen]byte
		prng.Read(salt[:])

		key, err := NewKdfKey(groupKey, uint32(i), salt)
		if err != nil {
			t.Errorf("NewKdfKey returned an error: %+v", err)
		}
		keyString := base64.StdEncoding.EncodeToString(key[:])

		if expected != keyString {
			t.Errorf("NewKdfKey did not return the expected key (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, keyString)
		}

		// fmt.Printf("\"%s\",\n", keyString)
	}
}

// Test that NewKdfKey returns unique keys when the group key and salt are
// changed individually.
func TestNewKdfKey_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	keys := map[string]bool{}
	var groupKey Key
	prng.Read(groupKey[:])
	var salt [SaltLen]byte
	prng.Read(salt[:])

	// Test changes to group key
	for i := 0; i < 100; i++ {
		key, err := NewKdfKey(groupKey, 0, salt)
		if err != nil {
			t.Errorf("NewKdfKey returned an error: %+v", err)
		}
		keyString := base64.StdEncoding.EncodeToString(key[:])

		if keys[keyString] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyString, i)
		} else {
			keys[keyString] = true
		}

		prng.Read(groupKey[:])
	}

	// Test changes to the salt
	for i := 0; i < 100; i++ {
		key, err := NewKdfKey(groupKey, 0, salt)
		if err != nil {
			t.Errorf("NewKdfKey returned an error: %+v", err)
		}
		keyString := base64.StdEncoding.EncodeToString(key[:])

		if keys[keyString] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyString, i)
		} else {
			keys[keyString] = true
		}

		prng.Read(salt[:])
	}

	// Test changes to the epoch
	for i := 0; i < 100; i++ {
		key, err := NewKdfKey(groupKey, uint32(i), salt)
		if err != nil {
			t.Errorf("NewKdfKey returned an error: %+v", err)
		}
		keyString := base64.StdEncoding.EncodeToString(key[:])

		if keys[keyString] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyString, i)
		} else {
			keys[keyString] = true
		}
	}
}

// Happy path.
func TestCryptKey_Bytes(t *testing.T) {
	expected := make([]byte, CryptKeyLen)
	rand.New(rand.NewSource(42)).Read(expected)
	var ck CryptKey
	copy(ck[:], expected)

	if !bytes.Equal(expected, ck.Bytes()) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, ck.Bytes())
	}
}

// Happy path.
func TestCryptKey_String(t *testing.T) {
	buff := make([]byte, CryptKeyLen)
	rand.New(rand.NewSource(42)).Read(buff)
	var ck CryptKey
	copy(ck[:], buff)

	expected := base64.StdEncoding.EncodeToString(buff)

	if expected != ck.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, ck.String())
	}
}

// Unit test of ComputeEpoch.
func TestComputeEpoch(t *testing.T) {
	timestamp := time.Unix(0, 0)
	if ComputeEpoch(timestamp) != 0 {
		t.Errorf("NewEpoch returned incorrect epoch for time %s."+
			"\nexpected: %d\nreceived: %d", timestamp, 0, ComputeEpoch(timestamp))
	}

	timestamp = timestamp.Add(epochPeriod - 1)
	if ComputeEpoch(timestamp) != 0 {
		t.Errorf("NewEpoch returned incorrect epoch for time %s."+
			"\nexpected: %d\nreceived: %d", timestamp, 0, ComputeEpoch(timestamp))
	}

	timestamp = timestamp.Add(1)
	if ComputeEpoch(timestamp) != 1 {
		t.Errorf("NewEpoch returned incorrect epoch for time %s."+
			"\nexpected: %d\nreceived: %d", timestamp, 1, ComputeEpoch(timestamp))
	}

	timestamp = timestamp.Add(epochPeriod)
	if ComputeEpoch(timestamp) != 2 {
		t.Errorf("NewEpoch returned incorrect epoch for time %s."+
			"\nexpected: %d\nreceived: %d", timestamp, 2, ComputeEpoch(timestamp))
	}
}
