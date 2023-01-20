////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"encoding/binary"

	"gitlab.com/xx_network/primitives/id"
)

var dmIDSalt = []byte("xxDMMessageIdSalt")

// DirectMessage objects are required to implement this interface.
type DirectMessage interface {
	GetRoundID() uint64
	GetPayload() []byte
	GetPayloadType() uint32
	GetNickname() string
	GetNonce() []byte
	GetLocalTimestamp() int64
}

// DeriveDirectMessageID hashes the parts relevant to a direct message
// to create a shared message ID between both parties.
// Round ID, Pubey, and DMToken is not hashed, so this is not replay
// resistant from a malicious attacker, but DMs prevent parties without the
// keys of one half the connection from participating.
func DeriveDirectMessageID(receptionID *id.ID, msg DirectMessage) ID {
	payloadType := make([]byte, 4)
	binary.LittleEndian.PutUint32(payloadType, msg.GetPayloadType())
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp,
		uint64(msg.GetLocalTimestamp()))

	return deriveID(receptionID, msg.GetRoundID(), msg.GetPayload(),
		payloadType, []byte(msg.GetNickname()), msg.GetNonce(),
		timestamp, dmIDSalt)
}
