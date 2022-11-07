////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"encoding/base64"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// MessageIdLen is the length, in bytes, of the message ID.
const MessageIdLen = 32

// MessageID is the 256-bit unique ID that identifies a message.
type MessageID [MessageIdLen]byte

// NewMessageID generates an ID for a group message by hashing the group ID and
// the internal message format.
func NewMessageID(groupID *id.ID, internalFormat []byte) MessageID {
	// Hash the group ID and the internal message format
	h, _ := blake2b.New256(nil)
	h.Write(groupID.Bytes())
	h.Write(internalFormat)

	var messageID MessageID
	copy(messageID[:], h.Sum(nil))

	return messageID
}

// Bytes returns the MessageID as a byte slice.
func (mid MessageID) Bytes() []byte {
	return mid[:]
}

// String returns the MessageID as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (mid MessageID) String() string {
	return base64.StdEncoding.EncodeToString(mid.Bytes())
}
