///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
)

const tagFpSalt = "singleUseTagFingerprintSalt"
const TagFpSize = 16

type TagFP [TagFpSize]byte

// NewTagFP generates the tag fingerprint used to identify the module that the
// transmission message belongs to. The tag can be anything, but should be long
// enough so that it is unique.
func NewTagFP(tag string) TagFP {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use "+
			"communication tag fingerprint: %v", err)
	}

	// Hash tag and salt
	h.Write([]byte(tag))
	h.Write([]byte(tagFpSalt))

	// Get hash bytes
	return UnmarshalTagFP(h.Sum(nil))
}

// UnmarshalTagFP generates a new TagFP from the specified bytes.
func UnmarshalTagFP(b []byte) TagFP {
	var tagFp TagFP
	copy(tagFp[:], b[:])
	return tagFp
}

// Bytes returns the tag fingerprint as a byte slice.
func (fp TagFP) Bytes() []byte {
	return fp[:]
}

// String returns the base64 string encoding of the tag fingerprint.
func (fp TagFP) String() string {
	return base64.StdEncoding.EncodeToString(fp[:])
}
