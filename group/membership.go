////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// A Membership is a list of members in a group. The group leader is always
// listed first and the following participants are sorted lexicographically. A
// member is defined by their ID and their Diffie–Hellman key.

package group

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
	"sort"
	"strconv"
	"strings"
)

// Error messages.
const (
	minParticipantsErr   = "number of participants %d < %d minimum allowed"
	maxParticipantsErr   = "number of participants %d > %d maximum allowed"
	minMembersErr        = "number of members %d < %d minimum allowed"
	maxMembersErr        = "number of members %d > %d maximum allowed"
	addExistingMemberErr = "membership list contains duplicate user IDs %s"
	unmarshalIdErr       = "failed to unmarshal ID: %+v"
	decodeDhKeyErr       = "failed to unmarshal Diffie–Hellman key: %+v"
)

// Lengths, in bytes, of serialized data sizes.
const (
	serialMembershipLenSize = 2
	serialDhKeyByteLenSize  = 2
)

const (
	// MinMembers is the minimum number of members allowed in a Membership list.
	MinMembers = 3

	// MaxMembers is the minimum number of members allowed in a Membership list.
	MaxMembers = 11

	// MinParticipants is the minimum number of participants allowed when
	// creating a new Membership list.
	MinParticipants = MinMembers - 1

	// MaxParticipants is the maximum number of participants allowed when
	// creating a new Membership list.
	MaxParticipants = MaxMembers - 1
)

// Membership is a list of members in a group. The group leader is always the
// first in the list followed by all group members sorted by their ID smallest
// to largest.
type Membership []Member

// Member describes each user in a group membership list.
type Member struct {
	ID    *id.ID      // Group member's user ID
	DhKey *cyclic.Int // Group member's public Diffie–Hellman key
}

// NewMembership returns a new Membership list with the provided leader and
// participants.
func NewMembership(leader contact.Contact, participants ...contact.Contact) (Membership, error) {
	// Return an error if there are too few or too many participants
	if len(participants) < MinParticipants {
		return nil, errors.Errorf(minParticipantsErr, len(participants), MinParticipants)
	} else if len(participants) > MaxParticipants {
		return nil, errors.Errorf(maxParticipantsErr, len(participants), MaxParticipants)
	}

	// Sort the membership list by ID
	sort.Slice(participants, func(i, j int) bool {
		return bytes.Compare(participants[i].ID.Bytes(), participants[j].ID.Bytes()) == -1
	})

	// Generate new Membership with a capacity to fit the leader and participants
	membership := make(Membership, 0, 1+len(participants))

	// Add the leader as the first member in the group
	membership = append(membership, contact2Member(leader))

	// Add all the participants to the membership list if they are not duplicates
	for i, c := range participants {
		// Return an error for duplicate user IDs
		if membership[i].ID.Cmp(c.ID) {
			return nil, errors.Errorf(addExistingMemberErr, c.ID)
		}
		membership = append(membership, contact2Member(c))
	}

	return membership, nil
}

// Digest generates a hash of all the reception IDs and Diffie–Hellman keys of
// each member in the order presented in the Membership list.
func (gm Membership) Digest() []byte {
	h, _ := blake2b.New256(nil)

	for _, member := range gm {
		if member.ID != nil {
			h.Write(member.ID.Bytes())
		}
		if member.DhKey != nil {
			h.Write(member.DhKey.Bytes())
		}
	}

	return h.Sum(nil)
}

// Serialize generates a byte representation of the Membership for sending over
// the wire.
func (gm Membership) Serialize() []byte {
	buff := bytes.NewBuffer(nil)

	// Write number of group members to the buffer
	b := make([]byte, serialMembershipLenSize)
	binary.PutVarint(b, int64(len(gm)))
	buff.Write(b)

	// Write each member to the buffer
	for _, member := range gm {
		member.serialize(buff)
	}

	return buff.Bytes()
}

// DeserializeMembership deserializes the bytes into a Membership.
func DeserializeMembership(b []byte) (Membership, error) {
	buff := bytes.NewBuffer(b)

	// Get number of members in list
	numMembers, _ := binary.Varint(buff.Next(serialMembershipLenSize))

	// Return an error if there are too few or too many members
	if numMembers < MinMembers {
		return nil, errors.Errorf(minMembersErr, numMembers, MinMembers)
	} else if numMembers > MaxMembers {
		return nil, errors.Errorf(maxMembersErr, numMembers, MaxMembers)
	}

	// Add each member to the membership list
	membership := make(Membership, numMembers)
	for i := 0; i < int(numMembers); i++ {
		var err error
		membership[i], err = deserializeMember(buff)
		if err != nil {
			return nil, err
		}
	}

	return membership, nil
}

// String returns a list of members as text. This functions satisfies the
// fmt.Stringer interface.
func (gm Membership) String() string {
	str := "{"

	if len(gm) > 0 {
		str += "Leader: " + gm[0].String() + ", Participants: "
	}

	var members string
	if len(gm) > 1 {
		var membersArr []string
		for i, m := range gm[1:] {
			membersArr = append(membersArr, strconv.Itoa(i)+": "+m.String())
		}

		members = strings.Join(membersArr, ", ")
	} else {
		members = "<nil>"
	}

	return str + members + "}"
}

// DeepCopy returns a deep copy of the Membership.
func (gm Membership) DeepCopy() Membership {
	membership := make(Membership, len(gm))
	for i, m := range gm {
		membership[i] = m.DeepCopy()
	}
	return membership
}

// Serialize generates a byte representation of the Member for sending over the
// wire.
func (m Member) Serialize() []byte {
	return m.serialize(&bytes.Buffer{})
}

// Serialize serializes the Member and write the bytes to the buffer.
func (m Member) serialize(buff *bytes.Buffer) []byte {
	// Write member's ID
	if m.ID != nil {
		buff.Write(m.ID.Marshal())
	} else {
		// Handle nil ID
		buff.Write(make([]byte, id.ArrIDLen))
	}

	// Binary encode member's DH key and write size to buffer
	b := make([]byte, serialDhKeyByteLenSize)
	var dhKey []byte
	if m.DhKey != nil {
		dhKey = m.DhKey.BinaryEncode()
		binary.PutVarint(b, int64(len(dhKey)))
	}
	buff.Write(b)

	// Write DH key
	buff.Write(dhKey)

	return buff.Bytes()
}

// DeserializeMember deserializes the bytes into a Member.
func DeserializeMember(b []byte) (Member, error) {
	return deserializeMember(bytes.NewBuffer(b))
}

// deserializeMember deserializes the bytes buffer into a Member.
func deserializeMember(buff *bytes.Buffer) (Member, error) {
	member := Member{DhKey: &cyclic.Int{}}
	var err error

	// Get and unmarshal ID
	member.ID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return member, errors.Errorf(unmarshalIdErr, err)
	}

	// If the ID is equal to all zeroes, then set it to nil
	if *member.ID == (id.ID{}) {
		member.ID = nil
	}

	// Get DH key size
	dhKeySize, _ := binary.Varint(buff.Next(serialDhKeyByteLenSize))

	// Get and decode DH key
	if dhKeySize == 0 {
		// Handle nil key
		member.DhKey = nil
	} else {
		if err = member.DhKey.BinaryDecode(buff.Next(int(dhKeySize))); err != nil {
			return member, errors.Errorf(decodeDhKeyErr, err)
		}
	}

	return member, nil
}

// DeepCopy returns a deep copy of the Member.
func (m Member) DeepCopy() Member {
	var newMember Member

	if m.ID != nil {
		newMember.ID = m.ID.DeepCopy()
	}

	if m.DhKey != nil {
		newMember.DhKey = m.DhKey.DeepCopy()
	}

	return m
}

// Equal returns true if the two Members have the same ID and Diffie–Hellman key.
func (m Member) Equal(x Member) bool {
	if (m.ID == nil && x.ID != nil) || (m.ID != nil && x.ID == nil) {
		return false
	}
	if (m.DhKey == nil && x.DhKey != nil) || (m.DhKey != nil && x.DhKey == nil) {
		return false
	}
	return ((m.ID == nil && x.ID == nil) || m.ID.Cmp(x.ID)) &&
		((m.DhKey == nil && x.DhKey == nil) || m.DhKey.Cmp(x.DhKey) == 0)
}

// String returns the member's ID and truncated Diffie–Hellman key as text.
// This functions satisfies the fmt.Stringer interface.
func (m Member) String() string {
	idString := "<nil>"
	if m.ID != nil {
		idString = m.ID.String()
	}

	dhKeyString := "<nil>"
	if m.DhKey != nil {
		dhKeyString = m.DhKey.Text(10)
	}

	return "{" + idString + ", " + dhKeyString + "}"
}

// GoString returns the member's ID and full Diffie–Hellman key as text. This
// functions satisfies the fmt.GoStringer interface.
func (m Member) GoString() string {
	idString := "<nil>"
	if m.ID != nil {
		idString = m.ID.String()
	}

	dhKeyString := "<nil>"
	if m.DhKey != nil {
		dhKeyString = m.DhKey.TextVerbose(10, 0)
	}

	return "group.Member{ID:" + idString + ", DhKey:" + dhKeyString + "}"
}

// contact2Member returns the contact.Contact as a Member with the same ID and
// Diffie–Hellman key.
func contact2Member(c contact.Contact) Member {
	var m Member

	if c.ID != nil {
		m.ID = c.ID.DeepCopy()
	}

	if c.DhPubKey != nil {
		m.DhKey = c.DhPubKey.DeepCopy()
	}

	return m
}
