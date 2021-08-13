////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package group

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"git.xx.network/xx_network/primitives/id"
	"math/rand"
	"strings"
	"testing"
)

// Consistency test of NewKey.
func TestNewKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedKeys := []string{
		"W3QGrWaeFNEbRmqMSGoSn183Wv0YVIsGexdimszPKdg=",
		"GjTtMhv6fGtLeirIrpzouwnNemX9eN03Li/BDzmdeCk=",
		"A8bhZP09wlTfee6o2LEWr7f5l79xbrnqtptGn8cE9cE=",
		"JajHwzXJuq3XuoTdRkcaoaZKx5oo6t9CoJAqT2d/hkg=",
		"kB2Kph7srsHbawPF4BHIjD+5u1D55QAurCWRM/nT1Go=",
		"aV/OhETJFSq9O+6iN0Gj5H7rU9zNaMH40bDV/oNclT0=",
		"8d2hwKX1+I5KWp8UIOguhQdZuJNbjWkFkvf8SSf6ot8=",
		"rVAG2iqXddaU7P/Lg6n5ZjTzh1yQDIhbGrbQ3sjsZOo=",
		"gArWVPNhkuACuMXHxHwbmCKwvHEEyO58RmvCICh18lo=",
		"g/4L1u0mfkK2H3i1dtMF6SgL1S/NQcZCAmNA6EBeIwA=",
	}

	for i, expected := range expectedKeys {
		membership, err := NewMembership(randContact(prng), randContact(prng), randContact(prng))
		if err != nil {
			t.Errorf("Failed to create new Membership (%d): %+v", i, err)
		}

		var preimage KeyPreimage
		prng.Read(preimage[:])

		key := NewKey(preimage, membership)

		keyString := base64.StdEncoding.EncodeToString(key[:])

		if expected != keyString {
			t.Errorf("NewKey did not return the expected ID (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, keyString)
		}

		// fmt.Printf("\"%s\",\n", keyString)
	}
}

// Test that NewKey returns unique keys when either the Membership or preimage
// change.
func TestNewKey_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	keys := map[string]bool{}
	membership, err := NewMembership(randContact(prng), randContact(prng), randContact(prng))
	if err != nil {
		t.Errorf("Failed to create new Membership: %+v", err)
	}
	var preimage KeyPreimage
	prng.Read(preimage[:])

	// Test changes to Membership
	for i := 0; i < 100; i++ {
		key := NewKey(preimage, membership)

		keyString := base64.StdEncoding.EncodeToString(key[:])

		if keys[keyString] {
			t.Errorf("Key %s already exists in the map (%d).", keyString, i)
		} else {
			keys[keyString] = true
		}

		membership = append(membership, Member{randID(prng, id.User), randCycInt(prng)})
	}

	// Test changes to preimage
	for i := 0; i < 100; i++ {
		key := NewKey(preimage, membership)
		keyString := base64.StdEncoding.EncodeToString(key[:])

		if keys[keyString] {
			t.Errorf("Key %s already exists in the map (%d).", keyString, i)
		} else {
			keys[keyString] = true
		}

		prng.Read(preimage[:])
	}
}

// Happy path.
func TestKey_Bytes(t *testing.T) {
	expected := make([]byte, KeyLen)
	rand.New(rand.NewSource(42)).Read(expected)
	var k Key
	copy(k[:], expected)

	if !bytes.Equal(expected, k.Bytes()) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, k.Bytes())
	}
}

// Happy path.
func TestKey_String(t *testing.T) {
	buff := make([]byte, KeyLen)
	rand.New(rand.NewSource(42)).Read(buff)
	var k Key
	copy(k[:], buff)

	expected := base64.StdEncoding.EncodeToString(buff)

	if expected != k.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, k.String())
	}
}

// Consistency test of NewKeyPreimage.
func TestNewKeyPreimage_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedIDs := []string{
		"U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=",
		"39ebTXZCm2F6DJ+fDTulWwzA1hRMiIU1hBrL4HCbB1g=",
		"CD9h03W8ArQd9PkZKeGP2p5vguVOdI6B555LvW/jTNw=",
		"uoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44=",
		"GwuvrogbgqdREIpC7TyQPKpDRlp4YgYWl4rtDOPGxPM=",
		"rnvD4ElbVxL+/b4MECiH4QDazS2IX2kstgfaAKEcHHA=",
		"ceeWotwtwlpbdLLhKXBeJz8FySMmgo4rBW44F2WOEGE=",
		"SYlH/fNEQQ7UwRYCP6jjV2tv7Sf/iXS6wMr9mtBWkrE=",
		"NhnnOJZN/ceejVNDc2Yc/WbXT+weG4lJGrcjbkt1IWI=",
		"kM8r60LDyicyhWDxqsBnzqbov0bUqytGgEAsX7KCDog=",
	}

	for i, expected := range expectedIDs {

		preimage, err := NewKeyPreimage(prng)
		if err != nil {
			t.Errorf("NewKeyPreimage produced an error (%d): %+v", i, err)
		}

		preimageString := base64.StdEncoding.EncodeToString(preimage[:])

		if expected != preimageString {
			t.Errorf("NewKeyPreimage did not return the expected preimage (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, preimageString)
		}

		// fmt.Printf("\"%s\",\n", preimageString)
	}
}

// Error path: error is returned when the reader encounters an error.
func TestNewKeyPreimage_ReaderError(t *testing.T) {
	expectedErr := strings.SplitN(readKeyPreimageErr, "%", 2)[0]

	_, err := NewKeyPreimage(strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewKeyPreimage did not produce the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: error is returned when the reader does not read the correct
// number of bytes.
func TestNewKeyPreimage_ReadLengthError(t *testing.T) {
	readerString := "a"
	expectedErr := fmt.Sprintf(readLenKeyPreimageErr, len(readerString), KeyPreimageLen)

	_, err := NewKeyPreimage(strings.NewReader(readerString))
	if err == nil || err.Error() != expectedErr {
		t.Errorf("NewKeyPreimage did not produce the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func TestKeyPreimage_Bytes(t *testing.T) {
	expected := make([]byte, KeyPreimageLen)
	rand.New(rand.NewSource(42)).Read(expected)
	var kp KeyPreimage
	copy(kp[:], expected)

	if !bytes.Equal(expected, kp.Bytes()) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, kp.Bytes())
	}
}

// Happy path.
func TestKeyPreimage_String(t *testing.T) {
	buff := make([]byte, KeyPreimageLen)
	rand.New(rand.NewSource(42)).Read(buff)
	var kp KeyPreimage
	copy(kp[:], buff)

	expected := base64.StdEncoding.EncodeToString(buff)

	if expected != kp.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, kp.String())
	}
}
