package channel

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"

	jww "github.com/spf13/jwalterweatherman"
)

const (
	MessageIDLen  = 32
	messageIDSalt = "ChannelsMessageIdSalt"
)

type MessageID [MessageIDLen]byte

// MakeMessageID returns the ID for the given serialized message
// Due to the fact that messages contain the round they are sent in,
// they are replay resistant. This property, when combined with the collision
// resistance of the hash function, ensures that an adversary will not be able
// to cause multiple messages to have the same ID
//
// they contain the channel id as well to ensure that if a user is in two channels
// which have messages with the same text sent to them in the same round, they
// will have different ID
//
// The MessageID is defined as the H(message|chID|salt) before the message has been
// encrypted but after padding has been added.
func MakeMessageID(message []byte, chID *id.ID) MessageID {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panicf("Failed to get Hash: %+v", err)
	}
	h.Write(message)
	h.Write(chID[:])
	h.Write([]byte(messageIDSalt))
	midBytes := h.Sum(nil)

	mid := MessageID{}
	copy(mid[:], midBytes)
	return mid
}

// Equals checks if two message IDs which are the same
// Not constant time
func (mid MessageID) Equals(mid2 MessageID) bool {
	return bytes.Equal(mid[:], mid2[:])
}

// String returns a base64 encoded message ID for debugging
// Adheres to the go stringer interface
func (mid MessageID) String() string {
	return "ChMsgID-" + base64.StdEncoding.EncodeToString(mid[:])
}

// Bytes returns a copy of the bytes in the message
func (mid MessageID) Bytes() []byte {
	bytesCopy := make([]byte, len(mid))
	copy(bytesCopy, mid[:])
	return bytesCopy
}

// DeepCopy returns a copy Message ID
func (mid MessageID) DeepCopy() MessageID {
	return mid
}
