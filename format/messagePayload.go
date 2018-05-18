package format

import (
	"errors"
	"fmt"
	"gitlab.com/privategrity/crypto/cyclic"
)

const (

	// Length and Position of the Payload Initialization Vector
	PIV_LEN   uint64 = 9
	PIV_START uint64 = 0
	PIV_END   uint64 = PIV_LEN

	// Length and Position of message payload
	DATA_LEN   uint64 = TOTAL_LEN - SID_LEN - PIV_LEN - PMIC_LEN
	DATA_START uint64 = PIV_END
	DATA_END   uint64 = DATA_START + DATA_LEN

	SID_LEN   uint64 = 8
	SID_START uint64 = DATA_END
	SID_END   uint64 = SID_START + SID_LEN

	// Length and Position of the Payload MIC
	PMIC_LEN   uint64 = 8
	PMIC_START uint64 = SID_END
	PMIC_END   uint64 = PMIC_START + PMIC_LEN
)

type Payload struct {
	payloadInitVect *cyclic.Int
	senderID        *cyclic.Int
	data            *cyclic.Int
	payloadMIC      *cyclic.Int
}

// Makes a new message for a certain sender.
// Splits the message into multiple if it is too long
func NewPayload(sender uint64, text string) ([]Payload, error) {
	if sender == 0 {
		return []Payload{}, errors.New(fmt.Sprintf(
			"Cannot build Message Payload; Invalid Sender ID: %v",
			sender))
	}

	// Split the payload into multiple sub-payloads if it is longer than the
	// maximum allowed
	data := []byte(text)

	var dataLst [][]byte

	for uint64(len(data)) > DATA_LEN {
		dataLst = append(dataLst, data[0:DATA_LEN])
		data = data[DATA_LEN:]
	}

	dataLst = append(dataLst, data)

	//Create a message payload for every sub-payload
	var payloadLst []Payload

	for _, datum := range dataLst {
		payload := Payload{
			cyclic.NewInt(0),
			cyclic.NewIntFromUInt(sender),
			cyclic.NewIntFromBytes(datum),
			cyclic.NewInt(0)}
		payloadLst = append(payloadLst, payload)
	}

	return payloadLst, nil
}

// This function returns a pointer to the Payload Initialization Vector
// This ensures that while the data can be edited, it cant be reallocated
func (p Payload) GetPayloadInitVect() *cyclic.Int {
	return p.payloadInitVect
}

// This function returns a pointer to the Sender ID
// This ensures that while the data can be edited, it cant be reallocated
func (p Payload) GetSenderID() *cyclic.Int {
	return p.senderID
}

// This function returns a pointer to the data payload
// This ensures that while the data can be edited, it cant be reallocated
func (p Payload) GetData() *cyclic.Int {
	return p.data
}

// This function returns a pointer to the payload MIC
// This ensures that while the data can be edited, it cant be reallocated
func (p Payload) GetPayloadMIC() *cyclic.Int {
	return p.payloadMIC
}

//Returns the SenderID as a uint64
func (p Payload) GetSenderIDUint() uint64 {
	return p.senderID.Uint64()
}

// Returns the serialized message payload
// Returns as a cyclic int because it is expected that the message will be
// immediately encrypted via cyclic int multiplication
func (p Payload) SerializePayload() *cyclic.Int {
	pbytes := make([]byte, TOTAL_LEN)

	// Copy the Payload Initialization Vector into the serialization
	copy(pbytes[PIV_START:PIV_END], p.payloadInitVect.LeftpadBytes(PIV_LEN))

	// Copy the Sender ID into the serialization
	copy(pbytes[SID_START:SID_END], p.senderID.LeftpadBytes(SID_LEN))

	// Copy the payload data into the serialization
	copy(pbytes[DATA_START:DATA_END], p.data.LeftpadBytes(DATA_LEN))

	// Copy the payloac MIC into the serialization
	copy(pbytes[PMIC_START:PMIC_END], p.payloadMIC.LeftpadBytes(PMIC_LEN))

	//Make sure the highest bit of the serialization is zero
	pbytes[0] = pbytes[0] & ZEROER

	return cyclic.NewIntFromBytes(pbytes)
}

//Returns a Deserialized Message Payload
func DeserializePayload(pSerial *cyclic.Int) Payload {
	pbytes := pSerial.LeftpadBytes(TOTAL_LEN)

	return Payload{
		cyclic.NewIntFromBytes(pbytes[PIV_START:PIV_END]),
		cyclic.NewIntFromBytes(pbytes[SID_START:SID_END]),
		cyclic.NewIntFromBytes(pbytes[DATA_START:DATA_END]),
		cyclic.NewIntFromBytes(pbytes[RMIC_START:RMIC_END]),
	}
}