////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/shuffle"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// Shows that NewMembership returns a list of members in the correct order when
// supplied a shuffled list of participants.
func TestNewMembership(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < 10; i++ {
		leader := randContact(prng)

		// Create list of shuffled IDs
		shuffleSlice := make([]uint64, 10)
		for j := range shuffleSlice {
			shuffleSlice[j] = uint64(j)
		}
		shuffle.Shuffle(&shuffleSlice)

		// Create list of shuffled participants
		participants := make([]contact.Contact, 10)
		for j := range participants {
			participants[shuffleSlice[j]] = contact.Contact{
				ID:       id.NewIdFromUInt(uint64(j), id.User, t),
				DhPubKey: randCycInt(prng),
			}
		}

		// Create new membership from leader and shuffled participants
		membership, err := NewMembership(leader, participants...)
		if err != nil {
			t.Errorf("NewMembership produced an error: %+v", err)
		}

		// Check that the first member is the leader
		if !membership[0].Equal(contact2Member(leader)) {
			t.Errorf("First member is not the leader."+
				"\nexpected: %s\nreceived: %s", contact2Member(leader), membership[0])
		}

		// Check that all the participants are in order
		for j, m := range membership[2:] {
			if bytes.Compare(m.ID.Bytes(), membership[j+1].ID.Bytes()) != 1 {
				t.Errorf("Members at %d and %d are not sorted."+
					"\nmember 1: %d\nmember 2: %d", j+1, j+2,
					binary.LittleEndian.Uint64(m.ID.Bytes()),
					binary.LittleEndian.Uint64(membership[j+1].ID.Bytes()))
			}
		}
	}
}

// Error path: show that NewMembership returns an error when there are too few
// participants.
func TestNewMembership_MinParticipantsError(t *testing.T) {
	participants := make([]contact.Contact, MinMembers-2)
	expectedErr := fmt.Sprintf(minParticipantsErr, len(participants), MinParticipants)

	_, err := NewMembership(contact.Contact{}, participants...)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewMembership did not produce an error for too few participants."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: show that NewMembership returns an error when there are too many
// participants.
func TestNewMembership_MaxParticipantsError(t *testing.T) {
	participants := make([]contact.Contact, MaxMembers)
	expectedErr := fmt.Sprintf(maxParticipantsErr, len(participants), MaxParticipants)

	_, err := NewMembership(contact.Contact{}, participants...)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewMembership did not produce an error for too many participants."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: show that NewMembership returns an error when a participant has
// the same ID as the leader.
func TestNewMembership_DuplicateLeaderIdError(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	participants := []contact.Contact{randContact(prng), leader, randContact(prng)}
	expectedErr := fmt.Sprintf(addExistingMemberErr, leader.ID)

	_, err := NewMembership(leader, participants...)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewMembership did not produce an error for duplicate IDs."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: show that NewMembership returns an error when two participants
// have the same ID.
func TestNewMembership_DuplicateMemberIdError(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	member := randContact(prng)
	participants := []contact.Contact{randContact(prng), member, randContact(prng), member, randContact(prng)}
	expectedErr := fmt.Sprintf(addExistingMemberErr, member.ID)

	_, err := NewMembership(leader, participants...)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("NewMembership did not produce an error for duplicate IDs."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Consistency test of Membership.Digest.
func TestMembership_Digest_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedDigest := []string{
		"dvyE1dhCTi29YB2YZhQVFT7/5UZdnYS7mzG+T3PIkxk=",
		"rVw6qZyFIJS/DVS0ERhITbkAesr1p5hKxSQHH930h08=",
		"ehvAXBb3emad6mAGHsqao6g9FUvnzAX4jiPrEgZ6RTA=",
		"dyEji8GDimzkWXEEUGSx6kF3jcPZozOC5nBI26SFPCU=",
		"SQFTn5Tk8Mi2U/6TJFxYjN/du9rzqMmnzPibWBSTZ0A=",
		"3uJGsGm/m+NScnblzWFvjC+Wnn+f7JQ9D7evck/Ep6M=",
		"F4Ac7TYiCnCN6inF6r5m0oL7CMO+E+MHWV4PKKWuLqE=",
		"+U/TnQCW4ScIRYP1kwTCu7lARz4QxkiSC7D0YRI+lvA=",
		"ZP49VsNXDYVJ8/y8hEoNBm6c7Y6ea633qGLetgSUV6k=",
		"k9zzNIzEOr8rLZ0V7btsUrQlQpFBrRU/SVstuMoIhBM=",
	}

	for i, expected := range expectedDigest {
		leader := randContact(prng)
		participants := make([]contact.Contact, 10)
		for j := range participants {
			participants[j] = randContact(prng)
		}

		membership, err := NewMembership(leader, participants...)
		if err != nil {
			t.Errorf("Failed to create new Membership (%d): %+v", i, err)
		}

		digest := base64.StdEncoding.EncodeToString(membership.Digest())
		// fmt.Printf("\"%s\",\n", digest)

		if expected != digest {
			t.Errorf("Digest did not return the expected digest (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, digest)
		}
	}
}

// Test that Membership.Digest returns unique digests when either the Membership
// changes.
func TestMembership_Digest_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	digests := map[string]bool{}
	leader := randContact(prng)
	participants := make([]contact.Contact, 0, MaxParticipants)
	participants = append(participants, randContact(prng), randContact(prng))

	for i := 0; i < 100; i++ {
		membership, err := NewMembership(leader, participants...)
		if err != nil {
			t.Errorf("Failed to create new Membership (%d): %+v", i, err)
		}

		digest := base64.StdEncoding.EncodeToString(membership.Digest())

		if digests[digest] {
			t.Errorf("Digest %s already exists in the map (%d).", digest, i)
		} else {
			digests[digest] = true
		}

		participants = append(participants, randContact(prng))
		if len(participants) > MaxParticipants {
			participants = participants[1:]
		}
	}
}

// Tests that Membership.Digest returns the expected digest when members have
// nil fields.
func TestMembership_Digest_NilMembership(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	gm := Membership{Member{}, randMember(prng), randMember(prng)}
	expected := []byte{183, 95, 225, 91, 231, 49, 162, 216, 157, 154, 78, 3,
		216, 213, 88, 242, 18, 29, 89, 189, 255, 182, 246, 246, 116, 23, 101,
		149, 219, 12, 39, 237}

	digest := gm.Digest()
	if !bytes.Equal(digest, expected) {
		t.Errorf("Digest failed to return the expected digest when a member "+
			"in the Membership has nil fields.\nexpected: %v\nreceived: %v",
			expected, digest)
	}
}

// Test that Membership.String returns the expected output.
func TestMembership_String(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	participants := []contact.Contact{randContact(prng), randContact(prng), randContact(prng)}
	expected := "{Leader: {U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVID, 3534334367... in GRP: 6SsQ/HAHUn...}, Participants: 0: {15ufnw07pVsMwNYUTIiFNYQay+BwmwdYCD9h03W8ArQD, 2010156224... in GRP: 6SsQ/HAHUn...}, 1: {3RqsBM4ux44bC6+uiBuCp1EQikLtPJA8qkNGWnhiBhYD, 2643318057... in GRP: 6SsQ/HAHUn...}, 2: {9PkZKU50joHnnku9b+NM3LqEPujWPoxP/hzr6lRtj6wD, 6603068123... in GRP: 6SsQ/HAHUn...}}"

	m, _ := NewMembership(leader, participants...)

	if expected != m.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, m.String())
	}
}

// Test that Membership.String returns the expected output when the Membership
// only has a leader.
func TestMembership_String_NoParticipants(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	expected := "{Leader: {U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVID, 3534334367... in GRP: 6SsQ/HAHUn...}, Participants: <nil>}"

	m := Membership{contact2Member(leader)}

	if expected != m.String() {
		t.Errorf("String failed to return the expected string."+
			"\nexpected: %s\nreceived: %s", expected, m.String())
	}
}

// Tests that a Membership that is serialised and deserialized matches the
// original.
func TestMembership_Serialize_DeserializeMembership(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	participants := make([]contact.Contact, 10)
	for j := range participants {
		participants[j] = randContact(prng)
	}

	membership, err := NewMembership(leader, participants...)
	if err != nil {
		t.Errorf("Failed to create new Membership: %+v", err)
	}

	data := membership.Serialize()

	newMembership, err := DeserializeMembership(data)
	if err != nil {
		t.Errorf("DeserializeMember returned an error: %+v", err)
	}

	if !reflect.DeepEqual(membership, newMembership) {
		t.Errorf("Deserialized Membership does not match original."+
			"\nexpected: %+v\nreceived: %+v", membership, newMembership)
	}
}

// Error path: show that DeserializeMembership returns an error when the number
// of members read from the buffer is less than the max allowed.
func TestDeserializeMembership_MinMembersError(t *testing.T) {
	data := make([]byte, serialMembershipLenSize)
	binary.PutVarint(data, MinMembers-1)
	expectedErr := fmt.Sprintf(minMembersErr, MinMembers-1, MinMembers)

	_, err := DeserializeMembership(data)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("DeserializeMember did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: show that DeserializeMembership returns an error when the number
// of members read from the buffer is greater than the max allowed.
func TestDeserializeMembership_MaxMembersError(t *testing.T) {
	data := make([]byte, serialMembershipLenSize)
	binary.PutVarint(data, MaxMembers+1)
	expectedErr := fmt.Sprintf(maxMembersErr, MaxMembers+1, MaxMembers)

	_, err := DeserializeMembership(data)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("DeserializeMember did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: show that DeserializeMembership returns an error if a Member
// cannot be deserialized.
func TestDeserializeMembership_MemberDeserializeError(t *testing.T) {
	data := make([]byte, serialMembershipLenSize)
	binary.PutVarint(data, 5)
	expectedErr := strings.SplitN(unmarshalIdErr, "%", 2)[0]

	_, err := DeserializeMembership(data)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("DeserializeMember did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Unit test of Membership.DeepCopy.
func TestMembership_DeepCopy(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	leader := randContact(prng)
	participants := make([]contact.Contact, 10)
	for j := range participants {
		participants[j] = randContact(prng)
	}

	membership, err := NewMembership(leader, participants...)
	if err != nil {
		t.Errorf("Failed to create new Membership: %+v", err)
	}

	membershipCopy := membership.DeepCopy()

	if !reflect.DeepEqual(membership, membershipCopy) {
		t.Errorf("DeepCopy failed to return a copy."+
			"\nexpected: %s\nreceived: %s", membership, membershipCopy)
	}

	for i, m := range membershipCopy {
		if &membership[i].ID == &m.ID {
			t.Errorf("DeepCopy failed to return a deep copy of the ID (%d)."+
				"\nexpected: %v\nreceived: %v", i, &membership[i].ID, &m.ID)
		}

		if &membership[i].DhKey == &m.DhKey {
			t.Errorf("DeepCopy failed to return a deep copy of the DH key (%d)."+
				"\nexpected: %v\nreceived: %v", i, &membership[i].DhKey, &m.DhKey)
		}
	}
}

// Serializes and deserializes multiple Members and compares the original to the
// deserialized.
func TestMember_Serialize_DeserializeMember(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	for i := 0; i < 10; i++ {
		member := Member{
			ID:    randID(prng, id.User),
			DhKey: randCycInt(prng),
		}

		memberBytes := member.Serialize()

		newMember, err := DeserializeMember(memberBytes)
		if err != nil {
			t.Errorf("DeserializeMember returned an error (%d): %+v", i, err)
		}

		if !member.Equal(newMember) {
			t.Errorf("Deserialized Member does not match original (%d)."+
				"\nexpected: %s\nreceived: %s", i, member, newMember)
		}
	}
}

// Tests that a Member with nil ID and D Hkey can be serialized and deserialized.
func TestMember_Serialize_DeserializeMember_NilMember(t *testing.T) {
	member := Member{}

	data := member.Serialize()

	newMember, err := DeserializeMember(data)
	if err != nil {
		t.Errorf("DeserializeMember returned an error: %+v", err)
	}

	if !member.Equal(newMember) {
		t.Errorf("Deserialized Member does not match original."+
			"\nexpected: %s\nreceived: %s", member, newMember)
	}
}

// Error path: shows that unmarshalIdErr is returned for an invalid ID.
func TestDeserializeMember_UnmarshalIdError(t *testing.T) {
	data := []byte{5}
	expectedErr := strings.SplitN(unmarshalIdErr, "%", 2)[0]

	newMember, err := DeserializeMember(data)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("DeserializeMember did not return the expected error for "+
			"invalid ID data.\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
	t.Log(newMember)
}

// Error path: shows that decodeDhKeyErr is returned for an invalid DH key.
func TestDeserializeMember_DecodeDhKeyError(t *testing.T) {
	data := id.NewIdFromString("testID", id.User, t)
	expectedErr := strings.SplitN(decodeDhKeyErr, "%", 2)[0]

	_, err := DeserializeMember(append(data.Bytes(), 2))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("DeserializeMember did not return the expected error for "+
			"invalid DH key data.\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Unit test of Member.DeepCopy.
func TestMember_DeepCopy(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	member := Member{
		ID:    randID(prng, id.User),
		DhKey: randCycInt(prng),
	}

	memberCopy := member.DeepCopy()

	if !member.Equal(memberCopy) {
		t.Errorf("DeepCopy failed to return a copy."+
			"\nexpected: %s\nreceived: %s", member, memberCopy)
	}

	if &member.ID == &memberCopy.ID {
		t.Errorf("DeepCopy failed to return a deep copy of the ID."+
			"\nexpected: %v\nreceived: %v", &member.ID, &memberCopy.ID)
	}

	if &member.DhKey == &memberCopy.DhKey {
		t.Errorf("DeepCopy failed to return a deep copy of the DH key."+
			"\nexpected: %v\nreceived: %v", &member.DhKey, &memberCopy.DhKey)
	}
}

// Tests that Member.DeepCopy returns a member with nil fields when copying a
// member with nil fields.
func TestMember_DeepCopy_NilMember(t *testing.T) {
	member := Member{}

	memberCopy := member.DeepCopy()

	if !member.Equal(memberCopy) {
		t.Errorf("DeepCopy failed to return a copy."+
			"\nexpected: %s\nreceived: %s", member, memberCopy)
	}

	if &member.ID == &memberCopy.ID {
		t.Errorf("DeepCopy failed to return a deep copy of the ID."+
			"\nexpected: %v\nreceived: %v", &member.ID, &memberCopy.ID)
	}

	if &member.DhKey == &memberCopy.DhKey {
		t.Errorf("DeepCopy failed to return a deep copy of the DH key."+
			"\nexpected: %v\nreceived: %v", &member.DhKey, &memberCopy.DhKey)
	}
}

// Unit test of Member.Equal.
func TestMember_Equal(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	idA := randID(prng, id.User)
	kyA := randCycInt(prng)
	idB := randID(prng, id.User)
	kyB := randCycInt(prng)
	values := []struct {
		a, b     Member
		expected bool
	}{
		{Member{idA, kyA}, Member{idA, kyA}, true},
		{Member{nil, kyA}, Member{nil, kyA}, true},
		{Member{idA, nil}, Member{idA, nil}, true},
		{Member{idA, kyA}, Member{idB, kyA}, false},
		{Member{idA, kyA}, Member{idA, kyB}, false},
		{Member{nil, kyA}, Member{idA, kyB}, false},
		{Member{idA, kyA}, Member{idA, nil}, false},
	}

	for i, val := range values {
		if val.a.Equal(val.b) != val.expected {
			t.Errorf("Equal should have returned %T (%d)\na: %s\nb: %s",
				val.expected, i, val.a, val.b)
		}
	}
}

// Consistency test of Member.String.
func TestMember_String_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedStrings := []string{
		"{U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVID, 3534334367... in GRP: 6SsQ/HAHUn...}",
		"{15ufnw07pVsMwNYUTIiFNYQay+BwmwdYCD9h03W8ArQD, 2010156224... in GRP: 6SsQ/HAHUn...}",
		"{9PkZKU50joHnnku9b+NM3LqEPujWPoxP/hzr6lRtj6wD, 6603068123... in GRP: 6SsQ/HAHUn...}",
		"{3RqsBM4ux44bC6+uiBuCp1EQikLtPJA8qkNGWnhiBhYD, 2643318057... in GRP: 6SsQ/HAHUn...}",
		"{invD4ElbVxL+/b4MECiH4QDazS2IX2kstgfaAKEcHHAD, 4157513341... in GRP: 6SsQ/HAHUn...}",
		"{55ai4SlwXic/BckjJoKOKwVuOBdljhBhSYlH/fNEQQ4D, 6482807720... in GRP: 6SsQ/HAHUn...}",
		"{wRYCP6iJdLrAyv2a0FaSsTYZ5ziWTf3Hno1TQ3NmHP0D, 5785305945... in GRP: 6SsQ/HAHUn...}",
		"{Grcjbkt1IWKQzyvrQsPKJzKFYPGqwGfOpui/RtSrK0YD, 5274380952... in GRP: 6SsQ/HAHUn...}",
		"{QCxg8d6XgoPUoJo2+WwglBdG4+1NpkaprotPp7T8OiAD, 1628829379... in GRP: 6SsQ/HAHUn...}",
		"{+hp17fHP0rO1EhnqeVM6v0SNLEedMmB1M5BZFMjMHPAD, 2628757933... in GRP: 6SsQ/HAHUn...}",
	}
	for i, expected := range expectedStrings {
		member := Member{
			ID:    randID(prng, id.User),
			DhKey: randCycInt(prng),
		}

		if expected != member.String() {
			t.Errorf("String returned unexpected string (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, member)
		}

		// fmt.Printf("\"%s\",\n", member.String())
	}
}

// Tests that Member.String produces the expected string for a Member with a nil
// ID and DH key.
func TestMember_String_NilMember(t *testing.T) {
	expected := "{<nil>, <nil>}"
	member := Member{}

	if expected != member.String() {
		t.Errorf("String returned unexpected string."+
			"\nexpected: %s\nreceived: %s", expected, member.String())
	}
}

// Consistency test of Member.GoString.
func TestMember_GoString_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedStrings := []string{
		"group.Member{ID:U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVID, DhKey:3534334367214237261 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:15ufnw07pVsMwNYUTIiFNYQay+BwmwdYCD9h03W8ArQD, DhKey:2010156224608899041 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:9PkZKU50joHnnku9b+NM3LqEPujWPoxP/hzr6lRtj6wD, DhKey:6603068123710785442 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:3RqsBM4ux44bC6+uiBuCp1EQikLtPJA8qkNGWnhiBhYD, DhKey:2643318057788968173 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:invD4ElbVxL+/b4MECiH4QDazS2IX2kstgfaAKEcHHAD, DhKey:4157513341729910236 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:55ai4SlwXic/BckjJoKOKwVuOBdljhBhSYlH/fNEQQ4D, DhKey:648280772094679011 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:wRYCP6iJdLrAyv2a0FaSsTYZ5ziWTf3Hno1TQ3NmHP0D, DhKey:5785305945910038487 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:Grcjbkt1IWKQzyvrQsPKJzKFYPGqwGfOpui/RtSrK0YD, DhKey:5274380952544653919 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:QCxg8d6XgoPUoJo2+WwglBdG4+1NpkaprotPp7T8OiAD, DhKey:1628829379025336882 in GRP: 6SsQ/HAHUns=}",
		"group.Member{ID:+hp17fHP0rO1EhnqeVM6v0SNLEedMmB1M5BZFMjMHPAD, DhKey:2628757933617101898 in GRP: 6SsQ/HAHUns=}",
	}
	for i, expected := range expectedStrings {
		member := Member{
			ID:    randID(prng, id.User),
			DhKey: randCycInt(prng),
		}

		if expected != member.GoString() {
			t.Errorf("GoString returned unexpected string (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, member.GoString())
		}

		// fmt.Printf("\"%s\",\n", member.GoString())
	}
}

// Tests that Member.GoString produces the expected string for a Member with a
// nil ID and DH key.
func TestMember_GoString_NilMember(t *testing.T) {
	expected := "group.Member{ID:<nil>, DhKey:<nil>}"
	member := Member{}

	if expected != member.GoString() {
		t.Errorf("GoString returned unexpected string."+
			"\nexpected: %s\nreceived: %s", expected, member.GoString())
	}
}

// Unit test of contact2Member.
func Test_contact2Member(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	c := randContact(prng)

	member := contact2Member(c)

	if !member.ID.Cmp(c.ID) {
		t.Errorf("contact2Member did not return a member with the correct ID."+
			"\nexpected ID: %s\nreceived ID: %s", c.ID, member.ID)
	}

	if member.DhKey.Cmp(c.DhPubKey) != 0 {
		t.Errorf("contact2Member did not return a member with the correct DH key."+
			"\nexpected key: %s\nreceived key: %s", c.DhPubKey.Text(10), member.DhKey.Text(10))
	}
}

// Tests that contact2Member returns a member with nil fields if the provided
// contact has nil fields.
func Test_contact2Member_NilMemberFields(t *testing.T) {
	var c contact.Contact

	member := contact2Member(c)

	if member.ID != nil {
		t.Errorf("contact2Member did not return a member with a nil ID."+
			"\nexpected ID: %v\nreceived ID: %s", nil, member.ID)
	}

	if member.DhKey != nil {
		t.Errorf("contact2Member did not return a member with a nil DH key."+
			"\nexpected key: %v\nreceived key: %s", nil, member.DhKey.Text(10))
	}
}

// randMember returns a member with a random ID and DH public key.
func randMember(rng *rand.Rand) Member {
	return Member{
		ID:    randID(rng, id.User),
		DhKey: randCycInt(rng),
	}
}

// randContact returns a contact with a random ID and DH public key.
func randContact(rng *rand.Rand) contact.Contact {
	return contact.Contact{
		ID:       randID(rng, id.User),
		DhPubKey: randCycInt(rng),
	}
}

// randID returns a new random ID of the specified type.
func randID(rng *rand.Rand, t id.Type) *id.ID {
	newID := &id.ID{}
	rng.Read(newID[:])
	newID.SetType(t)
	return newID
}

// randCycInt returns a random cyclic int.
func randCycInt(rng *rand.Rand) *cyclic.Int {
	return getGroup().NewInt(rng.Int63())
}

// getGroup returns a cyclic group.
func getGroup() *cyclic.Group {
	return cyclic.NewGroup(
		large.NewIntFromString("E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D4941"+
			"3394C049B7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688"+
			"B55B3DD2AEDF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861"+
			"575E745D31F8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC"+
			"718DD2A3E041023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FF"+
			"B1BC51DADDF453B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBC"+
			"A23EAC5ACE92096EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD"+
			"161C7738F32BF29A841698978825B4111B4BC3E1E198455095958333D776D8B2B"+
			"EEED3A1A1A221A6E37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C"+
			"4F50D7D7803D2D4F278DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F"+
			"1390B5D3FEACAF1696015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F"+
			"96789C38E89D796138E6319BE62E35D87B1048CA28BE389B575E994DCA7554715"+
			"84A09EC723742DC35873847AEF49F66E43873", 16),
		large.NewIntFromString("2", 16))
}
