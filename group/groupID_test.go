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

// Consistency test of NewID.
func TestNewID_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedIDs := []string{
		"wXQ3PP2W7BZW6BtX/j8LCZK5fPm1pPEiD4G7ngnyGS4E",
		"hRBMS9r9P5zo/aOI70S7Kt7CKQmdM42T0nYTuLuyqlcE",
		"6/qaRlMcUKAg734uC0Xfz/l6FC/scacWrMxziWQE1cUE",
		"dE0f7BoTjYBKpHlgkfhxV260+iWNiZ5kkLVp9DAWzMoE",
		"0oAdAqjDDDlcPmdIgWcELcS3MVs11jxURbOSLNftJs0E",
		"6KJiv9ArP43m0WO15kVGyDVCGmb6OfPmE5OVvMenPK4E",
		"rTl3Rgs/dTWq73IpRgAnmf6EPZskDvdfoUS3PeDyZY8E",
		"+ioPwYisvf7jhH4Sz4gTiL7cpLydpOFhASRU0iP0S/4E",
		"56fxgWtKxlo/WElSLfjmvqpfTDC4eXlux71aYDQmU4IE",
		"D0BlK19aFsx++HhLKqw8genLc1RzPzieuzTvj8GiMnME",
	}

	for i, expected := range expectedIDs {
		membership, err := NewMembership(randContact(prng), randContact(prng), randContact(prng))
		if err != nil {
			t.Errorf("Failed to create new Membership (%d): %+v", i, err)
		}
		var preimage IdPreimage
		prng.Read(preimage[:])

		gid := NewID(preimage, membership)

		if expected != gid.String() {
			t.Errorf("NewID did not return the expected ID (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, gid)
		}

		if gid.GetType() != id.Group {
			t.Errorf("ID has incorrect type (%d)."+
				"\nexpected: %s\nreceived: %s", i, id.Group, gid.GetType())
		}

		// fmt.Printf("\"%s\",\n", gid)
	}
}

// Test that NewID returns unique IDs when either the Membership or preimage
// change.
func TestNewID_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	ids := map[id.ID]bool{}
	membership, err := NewMembership(randContact(prng), randContact(prng), randContact(prng))
	if err != nil {
		t.Errorf("Failed to create new Membership: %+v", err)
	}
	var preimage IdPreimage
	prng.Read(preimage[:])

	// Test changes to Membership
	for i := 0; i < 100; i++ {
		gid := NewID(preimage, membership)

		if ids[*gid] {
			t.Errorf("ID %s already exists in the map (%d).", gid, i)
		} else {
			ids[*gid] = true
		}

		membership = append(membership, Member{randID(prng, id.User), randCycInt(prng)})
	}

	// Test changes to preimage
	for i := 0; i < 100; i++ {
		gid := NewID(preimage, membership)

		if ids[*gid] {
			t.Errorf("ID %s already exists in the map (%d).", gid, i)
		} else {
			ids[*gid] = true
		}

		prng.Read(preimage[:])
	}
}

// Consistency test of NewIdPreimage.
func TestNewIdPreimage_Consistency(t *testing.T) {
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
		preimage, err := NewIdPreimage(prng)
		if err != nil {
			t.Errorf("NewIdPreimage produced an error (%d): %+v", i, err)
		}

		preimageString := base64.StdEncoding.EncodeToString(preimage[:])

		if expected != preimageString {
			t.Errorf("NewIdPreimage did not return the expected preimage (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, preimageString)
		}

		// fmt.Printf("\"%s\",\n", preimageString)
	}
}

// Error path: error is returned when the reader encounters an error.
func TestNewIdPreimage_ReaderError(t *testing.T) {
	expectedErr := strings.SplitN(readIdPreimageErr, "%", 2)[0]

	_, err := NewIdPreimage(strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewIdPreimage did not produce the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: error is returned when the reader does not read the correct
// number of bytes.
func TestNewIdPreimage_ReadLengthError(t *testing.T) {
	readerString := "a"
	expectedErr := fmt.Sprintf(readLenIDPreimageErr, len(readerString), IdPreimageLen)

	_, err := NewIdPreimage(strings.NewReader(readerString))
	if err == nil || err.Error() != expectedErr {
		t.Errorf("NewIdPreimage did not produce the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func TestIdPreimage_Bytes(t *testing.T) {
	expected := make([]byte, IdPreimageLen)
	rand.New(rand.NewSource(42)).Read(expected)
	var idp IdPreimage
	copy(idp[:], expected)

	if !bytes.Equal(expected, idp.Bytes()) {
		t.Errorf("Bytes failed to return the expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, idp.Bytes())
	}
}

// Happy path.
func TestIdPreimage_String(t *testing.T) {
	buff := make([]byte, IdPreimageLen)
	rand.New(rand.NewSource(42)).Read(buff)
	var idp IdPreimage
	copy(idp[:], buff)

	expected := base64.StdEncoding.EncodeToString(buff)

	if expected != idp.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, idp.String())
	}
}
