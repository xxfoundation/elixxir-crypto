////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/hash"
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
