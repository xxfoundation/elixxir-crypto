////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"gitlab.com/xx_network/primitives/id"
	"time"
)

// SendReport is the report structure for e2e.Handler's SendE2e.
type SendReport struct {
	// RoundList is the list of rounds which the message payload
	// is sent.
	RoundList []id.Round

	// MessageId is the ID of the message sent.
	MessageId MessageID

	// SentTime is the time in which the message was sent.
	// More specifically it is when SendE2e is called.
	SentTime time.Time

	// KeyResidue is the residue of the key used for the first partition of the
	// message payload. The residue is a hash of the key and a salt.
	KeyResidue KeyResidue
}
