////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"gitlab.com/xx_network/crypto/csprng"
	"reflect"
	"testing"
)

func TestConstructIdentity(t *testing.T) {
	numtests := 100

	rng := &csprng.SystemRNG{}
	codenames := make([]string, 0, numtests)

	for i := 0; i < numtests; i++ {
		id, _ := GenerateIdentity(rng)
		codenames = append(codenames, id.Codename+"#"+id.Extension+
			id.Color)
	}

	for i := 0; i < numtests; i++ {
		for j := i + 1; j < numtests; j++ {
			if codenames[i] == codenames[j] {
				t.Errorf("2 generated codenames are the same, %d vs %d",
					i, j)
			}
		}
	}
}

// Checks that PrivateIdentity.Marshal and UnmarshalPrivateIdentity are inverse
// operations.
func TestPrivateIdentity_MarshalUnmarshal(t *testing.T) {

	rng := &csprng.SystemRNG{}
	privateIdentity, _ := GenerateIdentity(rng)
	marshalledData := privateIdentity.Marshal()

	receivedIdentity, err := UnmarshalPrivateIdentity(marshalledData)
	if err != nil {
		t.Fatalf("UnmarshalPrivateIdentity error: %+v", err)
	}

	if !reflect.DeepEqual(receivedIdentity, privateIdentity) {
		t.Fatalf("UnmarshalPrivateIdentity did not construct identical "+
			"identity from original structure."+
			"\nExpected: %v"+
			"\nReceived: %v", privateIdentity, receivedIdentity)
	}

}

// Checks that Identity.Marshal and UnmarshalIdentity are inverse
// operations.
func TestIdentity_MarshalUnmarshal(t *testing.T) {

	rng := &csprng.SystemRNG{}
	privateIdentity, _ := GenerateIdentity(rng)
	expected := privateIdentity.Identity
	marshalledData := expected.Marshal()

	received, err := UnmarshalIdentity(marshalledData)
	if err != nil {
		t.Fatalf("UnmarshalIdentity error: %+v", err)
	}

	if !reflect.DeepEqual(expected, received) {
		t.Fatalf("UnmarshalIdentity did not construct identical identity "+
			"from orignal structure."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}

}

// Error case: UnmarshalPrivateIdentity should error when receiving
// byte data that is not of length
// [ed25519.PrivateKeySize] + [ed25519.PublicKeySize] + 1.
func TestUnmarshalPrivateIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalPrivateIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalPrivateIdentity should error when receiving byte data " +
			"that is too short.")
	}
}

// Error case: UnmarshalIdentity should error when receiving
// byte data that is not of length [ed25519.PublicKeySize] + 1.
func TestUnmarshalIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalIdentity should error when receiving byte data " +
			"that is too short.")
	}
}