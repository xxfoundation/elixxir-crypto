package channel

import (
	"bytes"
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"

	jww "github.com/spf13/jwalterweatherman"
)

const (
	// MessageIDLen is the length of a MessageID.
	MessageIDLen  = 32
	messageIDSalt = "ChannelsMessageIdSalt"
)

// Error messages.
const (
	unmarshalMessageIdDataLenErr = "received %d bytes when %d bytes required"
)

// MessageID is the unique identifier of a channel message.
type MessageID [MessageIDLen]byte

// MakeMessageID returns the MessageID for the given serialized message.
//
// Due to the fact that messages contain the round they are sent in, they are
// replay resistant. This property, when combined with the collision resistance
// of the hash function, ensures that an adversary will not be able to cause
// multiple messages to have the same ID.
//
// The MessageID contain the channel ID as well to ensure that if a user is in
// two channels that have messages with the same text sent to them in the same
// round, the message IDs will differ.
//
// Before the message has been encrypted but after padding has been added, the
// MessageID is defined as:
//
//	H(message | chID | salt)
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

// Equals checks if two message IDs are the same.
//
// Not constant time.
func (mid MessageID) Equals(mid2 MessageID) bool {
	return bytes.Equal(mid[:], mid2[:])
}

// String returns a base64 encoded MessageID for debugging. This function
// adheres to the fmt.Stringer interface.
func (mid MessageID) String() string {
	return "ChMsgID-" + base64.StdEncoding.EncodeToString(mid[:])
}

// Bytes returns a copy of the bytes in the message.
func (mid MessageID) Bytes() []byte {
	return mid.Marshal()
}

// DeepCopy returns a copy Message ID
func (mid MessageID) DeepCopy() MessageID {
	return mid
}

// Marshal marshals the MessageID into a byte slice.
func (mid MessageID) Marshal() []byte {
	bytesCopy := make([]byte, len(mid))
	copy(bytesCopy, mid[:])
	return bytesCopy
}

// UnmarshalMessageID unmarshalls the byte slice into a MessageID.
func UnmarshalMessageID(data []byte) (MessageID, error) {
	mid := MessageID{}
	if len(data) != MessageIDLen {
		return mid, errors.Errorf(
			unmarshalMessageIdDataLenErr, len(data), MessageIDLen)
	}

	copy(mid[:], data)
	return mid, nil
}
