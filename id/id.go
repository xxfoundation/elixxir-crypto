////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package id

import (
	"encoding/base32"
	"gitlab.com/privategrity/crypto/hash"
	"testing"
	"encoding/binary"
)

// Most string types in most languages (with C excepted) support 0 as a
// character in a string, for Unicode support. So it's possible to use normal
// strings as an immutable container for bytes in all the languages we care
// about supporting.
type UserID [UserIDLen]byte

// Length of IDs in bytes
// 256 bits
const UserIDLen = 32

// Use this if you don't want to have to populate user ids for this manually
var ZeroID UserID

// Length of registration code in raw bytes
// Must be a multiple of 5 bytes to work with base 32
// 8 character long reg codes when base-32 encoded currently with length of 5
const RegCodeLen = 5

func (u UserID) RegistrationCode() string {
	return base32.StdEncoding.EncodeToString(UserHash(u))
}

// UserHash generates a hash of the UID to be used as a registration code for
// demos
// TODO Should we use the full-length hash? Should we even be doing registration
// like this?
func UserHash(uid UserID) []byte {
	h, _ := hash.NewCMixHash()
	h.Write(uid[:])
	huid := h.Sum(nil)
	huid = huid[len(huid)-RegCodeLen:]
	return huid
}

// Only tests should use this method for compatibility with the old user ID
// structure, as a utility method to easily create user IDs with the correct
// length. So this func takes a testing.T.
func NewUserIDFromUint(newId uint64, t *testing.T) UserID {
	// TODO Uncomment these lines to cause failure where this method's used in
	// the real codebase. Then, replace those occurrences with better code.
	//t.Log("Warning: Creating a new user ID from uint. " +
	//	"You should create user IDs some other way.")
	var result UserID
	const sizeofUint64 = 8
	binary.BigEndian.PutUint64(result[UserIDLen - sizeofUint64:], newId)
	return result
}

// In most situations we only need to compare IDs for equality.
// Adding a number to an ID, or incrementing an ID, will normally have no meaning.
// This function therefore takes a testing.T to make sure that only test
// functions can call this method.
func (u UserID) NextID(t *testing.T) UserID {
	// TODO Uncomment these lines to cause failure where this method's used in
	// the real codebase. Then, replace those occurrences with better code.
	//t.Log("Warning: Getting the next consecutive ID. " +
	//	"This fundamentally makes no sense and you should cut it out.")

	// increment byte by byte starting from the end of the array
	for i := UserIDLen - 1; i >= 0; i-- {
		u[i]++
		if u[i] != 0 {
			break
		}
	}
	return u
}
