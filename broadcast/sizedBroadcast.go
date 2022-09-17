////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
"encoding/binary"
"github.com/pkg/errors"
	"io"
)

// Message field sizes.
const (
	// size of the size field
	sizeSize              = 2

	// minimumPadding is the minimum number of bytes of random padding
	// that will be appended n a message
	minimumPadding = 8

	// size of all extra space in the packet
	sizedBroadcastMinSize = sizeSize + minimumPadding

)

// Error messages.
const (
	// NewSizedBroadcast
	errNewSizedBroadcastMaxSize = "size of payload and its size %d too large to fit in max payload size %d"

	// DecodeSizedBroadcast
	errDecodeSizedBroadcastDataLen = "size of data %d must be greater than %d"
	errDecodeSizedBroadcastSize    = "stated payload size %d larger than provided data %d"


)

/*
+---------------------------------------------+
|            cMix Message Contents            |
+---------+-----------------+-----------------+
|  Size   |     Payload     |     padding     |
| 2 bytes | remaining space |   min 8 bytes   |
+---------+-----------------+-----------------+
*/

// NewSizedBroadcast creates a new broadcast payload of size maxPayloadSize that
// contains the given payload so that it fits completely inside a broadcasted
// cMix message payload. The length of the payload is stored internally and used
// to strip extraneous padding when decoding the payload.
// The maxPayloadSize is the maximum size of the resulting payload. Returns an
// error when the provided payload cannot fit in the max payload size.
func NewSizedBroadcast(outerPayloadSize int, payload []byte, rng io.Reader) ([]byte, error) {
	if len(payload)+sizedBroadcastMinSize > outerPayloadSize {
		return nil, errors.Errorf(errNewSizedBroadcastMaxSize,
			len(payload)+sizedBroadcastMinSize, outerPayloadSize)
	}

	sizedPayload := make([]byte, outerPayloadSize)
	binary.LittleEndian.PutUint16(sizedPayload[:sizeSize], uint16(len(payload)))

	copy(sizedPayload[sizeSize:sizeSize+len(payload)],payload)
	n, err := rng.Read(sizedPayload[sizeSize+len(payload):])
	if n!= outerPayloadSize - len(payload) - sizeSize{
		return nil, errors.New("failed to read the correct number of " +
			"bytes of randomness for the padding")
	}else if err!=nil{
		return nil, err
	}

	return sizedPayload, nil
}

// DecodeSizedBroadcast decodes the data into its original payload stripping off
// extraneous padding.
func DecodeSizedBroadcast(data []byte) ([]byte, error) {
	if len(data) < sizedBroadcastMinSize {
		return nil, errors.Errorf(
			errDecodeSizedBroadcastDataLen, len(data), sizedBroadcastMinSize)
	}

	size := GetSizedBroadcastSize(data)
	if len(data[sizeSize:])<int(size) {
		return nil, errors.Errorf(
			errDecodeSizedBroadcastSize, size, len(data[sizeSize:]))
	}

	return data[sizeSize : size+sizeSize], nil
}

// GetSizedBroadcastSize returns the size of the sized broadcast, used for
// testing
func GetSizedBroadcastSize(data []byte) uint16 {
	if len(data) < sizeSize {
		return 0
	}

	return binary.LittleEndian.Uint16(data[:sizeSize])
}

// MaxSizedBroadcastPayloadSize returns the maximum size of a payload that can
// fit in a sized broadcast message for the given maximum cMix message payload
// size.
func MaxSizedBroadcastPayloadSize(outerPayloadSize int) int {
	return outerPayloadSize - sizedBroadcastMinSize
}

