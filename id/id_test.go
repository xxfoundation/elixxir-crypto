package id

import (
	"testing"
	"math/rand"
	"encoding/binary"
	"bytes"
)

func TestUserID_RegistrationCode(t *testing.T) {
	// EXPERIMENT
	expected := "RUHPS2MI" // reg code for user 1
	var id UserID
	copy(id[len(id)-1:], []byte{0x01})
	actual := id.RegistrationCode()
	if actual != expected {
		t.Errorf("Registration code differed from expected. Got %v, "+
			"expected %v", actual, expected)
	}
}

func TestNewUserIDFromUint(t *testing.T) {
	// This particular method for new-ing a user ID is only able to fill out
	// the bytes on the little end
	intId := uint64(rand.Int63())
	id := NewUserIDFromUint(intId, t)
	// The first 64*3 bits should be left at zero
	for i := 0; i < sizeofUint64*3; i++ {
		if id[i] != 0 {
			t.Error("A byte that should have been zero wasn't")
		}
	}
	// The last bits should be the same starting at the big end of the int ID
	intIdBigEndian := make([]byte, 64/8)
	binary.BigEndian.PutUint64(intIdBigEndian, intId)
	if !bytes.Equal(intIdBigEndian, id[sizeofUint64*3:]) {
		t.Error("A byte that NewUserIDFromUint set wasn't identical to the" +
			" uint64 input")
	}
}

func TestUserID_SetBytes(t *testing.T) {
	idBytes := make([]byte, UserIDLen)
	rand.Read(idBytes)
	id, err := new(UserID).SetBytes(idBytes)
	if err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(id[:], idBytes) {
		t.Error("SetBytes didn't set all the bytes correctly")
	}
}

func TestUserID_SetBytes_Error(t *testing.T) {
	var idBytes []byte
	id, err := new(UserID).SetBytes(idBytes)
	if err == nil {
		t.Error("Didn't get an expected error from a too-short bytes")
	}
	if id != nil {
		t.Error("Got an ID out of setting the bytes, but shouldn't have")
	}
}

func TestUserID_SetUints(t *testing.T) {
	uints := [4]uint64{798264,350789,34076,154268}
	id := new(UserID).SetUints(&uints)
	for i := 0; i < len(uints); i++ {
		if binary.BigEndian.Uint64(id[i*8:]) != uints[i] {
			t.Errorf("Uint64 differed at index %v", i)
		}
	}
}

func TestUserID_Bytes(t *testing.T) {
	idBytes := make([]byte, UserIDLen)
	rand.Read(idBytes)
	id, err := new(UserID).SetBytes(idBytes)
	if err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(idBytes, id.Bytes()) {
		t.Error("Surprisingly, " +
			"the Bytes() method didn't return an equivalent byteslice")
	}
}
