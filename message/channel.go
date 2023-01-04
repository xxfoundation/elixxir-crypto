////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"gitlab.com/xx_network/primitives/id"
)

var chIDSalt = []byte("xxChMessageIdSalt")

// DeriveChannelMessageID returns the channel message ID for the given
// serialized message.
//
// Due to the fact that messages contain the round they are sent in, they are
// replay resistant. This property, when combined with the collision resistance
// of the hash function, ensures that an adversary will not be able to cause
// multiple messages to have the same ID.
//
// The MessageID contain the target ID (channel ID or recipient ID) as
// well to ensure that if a user is, e.g., in two channels that have messages
// with the same text sent to them in the same round, the message IDs
// will differ.
//
// The channel message ID is defined as:
//
//	H(chID | roundID | message | chIDSalt)
func DeriveChannelMessageID(chID *id.ID, roundID uint64,
	message []byte) ID {
	return deriveID(chID, roundID, message, chIDSalt)
}
