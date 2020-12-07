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
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
)

const MessageIDLen = 32

type MessageID [MessageIDLen]byte

// The message ID is probabilistically unique due to the uniqueness of the
// relationship fingerprint and the conversation ID
func NewMessageID(relationshipFingerprint []byte, conversationID uint64) MessageID {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to get hash for messageID creation")
	}
	h.Write(relationshipFingerprint)

	cIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(cIDBytes, conversationID)
	h.Write(cIDBytes)

	midBytes := h.Sum(nil)

	mid := MessageID{}
	copy(mid[:], midBytes)
	return mid
}

// Unmarshals a message id from a byte slice binary format.  Returns an error
// if the passed byte slice is the wrong length
func UnmarshalMessageID(b []byte) (MessageID, error) {
	if len(b) != MessageIDLen {
		return MessageID{}, errors.New("binary message ID is the " +
			"wrong length")
	}

	mid := MessageID{}
	copy(mid[:], b)
	return mid, nil
}

// Adheres to the stringer interface to return a truncated base64 encoded string
// of the message ID
func (mid MessageID) String() string {
	return mid.StringVerbose()[:8] + "..."
}

// Returns an un truncated base64 encoding of the message iD
func (mid MessageID) StringVerbose() string {
	s := base64.StdEncoding.EncodeToString(mid[:])
	return s
}

// Marshals the message ID into a binary format
func (mid MessageID) Marshal() []byte {
	return mid[:]
}
