////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package format

import (
	"errors"
	"fmt"
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/id"
)

// Defines message structure.  Based the "Basic Message Structure" doc
// Defining rangings in slices in go is inclusive for the beginning but
// exclusive for the end, so the END consts are one more then the final
// index.
const (
	TOTAL_LEN uint64 = 256

	//Byte used to ensure the highest bit of a serilization is zero
	ZEROER byte = 0x7F
)

//TODO: generate ranges programmatic

// Interface used to pass message data across gomobile bindings
type MessageInterface interface {
	// Returns the message's sender ID
	// (uint64) BigEndian serialized into a byte slice
	GetSender() *id.UserID
	// Returns the message payload
	GetPayload() string
	// Returns the message's recipient ID
	// (uint64) BigEndian serialized into a byte slice
	GetRecipient() *id.UserID
}

// Holds the payloads once they have been serialized
type MessageSerial struct {
	Payload   *cyclic.Int
	Recipient *cyclic.Int
}

// Structure which contains a message payload and the recipient payload in an
// easily accessible format
type Message struct {
	Payload
	Recipient
}

//Returns a serialized sender ID for the message interface
func (m Message) GetSender() *id.UserID {
	result, _ := new(id.UserID).SetBytes(m.senderID.LeftpadBytes(SID_LEN))
	return result
}

//Returns the payload as a string for the message interface
func (m Message) GetPayload() string {
	return string(m.data.Bytes())
}

//Returns a serialized recipient id for the message interface
// FIXME Two copies for this isn't great
func (m Message) GetRecipient() *id.UserID {
	result, _ := new(id.UserID).SetBytes(m.recipientID.LeftpadBytes(RID_LEN))
	return result
}

// Makes a new message for a certain sender and recipient
func NewMessage(sender, recipient *id.UserID, text string) ([]Message, error) {

	//build the recipient payload
	recipientPayload, err := NewRecipientPayload(recipient)

	if err != nil {
		err = errors.New(fmt.Sprintf(
			"Unable to build message due to recipient error: %s",
			err.Error()))
		return nil, err
	}

	//Build the message Payloads
	messagePayload, err := NewPayload(sender, text)

	if err != nil {
		err = errors.New(fmt.Sprintf(
			"Unable to build message due to message error: %s",
			err.Error()))
		return nil, err
	}

	messageList := make([]Message, len(messagePayload))

	for indx, pld := range messagePayload {
		messageList[indx] = Message{pld, recipientPayload.DeepCopy()}
	}

	return messageList, nil
}

func (m Message) SerializeMessage() MessageSerial {
	return MessageSerial{m.Payload.SerializePayload(),
		m.Recipient.SerializeRecipient()}
}

func DeserializeMessage(ms MessageSerial) Message {
	return Message{DeserializePayload(ms.Payload),
		DeserializeRecipient(ms.Recipient)}
}
