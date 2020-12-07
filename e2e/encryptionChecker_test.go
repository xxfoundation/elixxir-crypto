/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package e2e

import (
	"bytes"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
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

	SetUnencrypted(m, &uid)

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
