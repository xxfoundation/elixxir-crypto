////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"math/rand"
	"testing"

	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
)

const messageSize = 150

// Tests if IsUnencrypted() correctly determines an encrypted message as
// encrypted.
func TestIsUnencrypted_EncryptedMessage(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, messageSize)
	rand.Read(randSlice)
	fpSlice := make([]byte, format.KeyFPLen)
	rand.Read(fpSlice)
	fpSlice[0] &= 0x7f
	macSlice := make([]byte, format.MacLen)
	rand.Read(macSlice)
	macSlice[0] &= 0x7f

	// Create message
	m := format.NewMessage(messageSize)
	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)

	//set the fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], fpSlice)
	m.SetKeyFP(fp)

	m.SetMac(macSlice)

	// Check the message
	unencrypted, uid := IsUnencrypted(m)

	if unencrypted == true {
		t.Errorf("IsUnencrypted() determined the message is "+
			"unencrypted when it is actually encrypted"+
			"\n\treceived: %v\n\texpected: %v",
			unencrypted, false)
	}

	if uid != nil {
		t.Errorf("IsUnencrypted() should not return a user id on an" +
			"encrypted message")
	}
}

// Tests if IsUnencrypted() correctly determines an unencrypted message as
// unencrypted.
func TestIsUnencrypted_UnencryptedMessage(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, messageSize)
	rand.Read(randSlice)
	fpSlice := make([]byte, format.KeyFPLen)
	rand.Read(fpSlice)
	fpSlice[0] &= 0x7f

	// Create message
	m := format.NewMessage(messageSize)

	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)

	// Create new hash
	h, _ := hash.NewCMixHash()
	h.Write(m.GetContents())
	payloadHash := h.Sum(nil)
	payloadHash[0] &= 0x3F

	// Set the MAC with the high bit from the fingerprint as the ID
	m.SetMac(payloadHash)

	//set the fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], fpSlice)
	m.SetKeyFP(fp)

	// Check the message
	unencrypted, uid := IsUnencrypted(m)

	if unencrypted == false {
		t.Errorf("IsUnencrypted() determined the message is encrypted when it is actually unencrypted"+
			"\n\treceived: %v\n\texpected: %v",
			unencrypted, true)
	}

	expectedUID := id.ID{}
	copy(expectedUID[:], fpSlice[:])
	expectedUID[0] |= (payloadHash[0] & 0b01000000) << 1
	expectedUID.SetType(id.User)

	if !bytes.Equal(uid[:], expectedUID[:]) {
		t.Errorf("IsUnencrypted() returned the wrong userID"+
			"\n\treceived: %s\n\texpected: %s",
			uid, expectedUID)
	}
}

// Tests if SetUnencrypted() makes a message unencrypted according to
// IsUnencrypted().
func TestSetUnencrypted(t *testing.T) {
	// Generate random byte slice
	randSlice := make([]byte, messageSize)
	rand.Read(randSlice)

	// Create message
	m := format.NewMessage(messageSize)

	// Set message payload
	m.SetPayloadA(randSlice)
	m.SetPayloadB(randSlice)

	uid := id.ID{}
	rand.Read(uid[:32])
	uid.SetType(id.User)

	mac, fp := SetUnencrypted(m.GetContents(), &uid)
	m.SetKeyFP(fp)
	m.SetMac(mac)

	encrypted, rtnUid := IsUnencrypted(m)

	if encrypted == false {
		t.Errorf("SetUnencrypted() determined the message is encrypted"+
			" when it should be unencrypted\n\treceived: %v\n\texpected: %v",
			encrypted, true)
	}

	if !bytes.Equal(uid[:], rtnUid[:]) {
		t.Errorf("IsUnencrypted() returned the wrong userID"+
			"\n\treceived: %s\n\texpected: %s",
			rtnUid, uid)
	}
}

func TestIsUnencrypted(t *testing.T) {
	data := []byte{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		19, 0, 0, 8, 1, 0, 0, 0, 2, 22, 232, 2, 46, 248, 2, 254, 9,
		72, 101, 108, 108, 111, 44, 32, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 32, 247, 214, 254, 66, 103, 193, 216, 248, 208, 130, 239,
		184, 167, 82, 20, 44, 239, 245, 109, 2, 102, 37, 93, 208, 135,
		149, 48, 125, 190, 190, 223, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	m := format.NewMessage(512)
	m.SetRawContents(data)
	// Sets appropriate mac for success case in IsUnencrypted
	m.SetMac([]byte{0x38, 0x18, 0xd2, 0x77, 0x71, 0x2, 0xba, 0x6c, 0x87, 0xe1, 0x99, 0xe5, 0x79, 0xd6, 0x7b, 0x93,
		0x3c, 0x7d, 0xfe, 0x6a, 0xd5, 0xf2, 0xeb, 0x99, 0xa2, 0xa1, 0x9b, 0xaf, 0xb5, 0xe6, 0x67, 0xf9})
	encrypted, rtnUid := IsUnencrypted(m)
	if rtnUid == nil {
		t.Errorf("This should not be nil")
	}

	if !encrypted {
		t.Errorf("This should not be encrypted")
	}
}
