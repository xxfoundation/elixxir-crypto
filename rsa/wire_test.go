////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"golang.org/x/crypto/blake2b"
	"runtime"
	"testing"
)

func TestMarshalUnMarshalWire(t *testing.T) {
	sLocal := GetScheme()
	serverPrivKey, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.Public()
	serverPubKeyBytes := serverPubKey.MarshalWire()
	serverPubKey2, err := sLocal.UnmarshalPublicKeyWire(serverPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	serverPubKey2Bytes := serverPubKey2.MarshalWire()
	if !bytes.Equal(serverPubKeyBytes, serverPubKey2Bytes) {
		t.Fatal("byte slices don't match")
	}

	hashFunc := crypto.BLAKE2b_256

	// Javascript only uses SHA-256
	if runtime.GOOS == "js" {
		hashFunc = crypto.SHA256
		t.Log("Javascript environment; using SHA-256.")
	}

	message := []byte("fluffy bunny")
	hashed := blake2b.Sum256(message)
	signature, err :=
		serverPrivKey.SignPSS(rand.Reader, hashFunc, hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	err = serverPubKey2.VerifyPSS(hashFunc, hashed[:], signature, nil)
	if err != nil {
		t.Fatal(err)
	}
}

// Smoke test.
func TestPublic_GetMarshalWireLength(t *testing.T) {
	sLocal := GetScheme()
	val := 24

	// This is the equation used in GetMarshalWireLength as of writing
	expectedVal := val + ELength
	if sLocal.GetMarshalWireLength(val) != expectedVal {
		t.Fatalf("GetMarshalWireLength did not return expected value."+
			"\nexpected: %d\nreceived: %d",
			expectedVal, sLocal.GetMarshalWireLength(val))
	}
}

// Error case: tests that passing in bytes that are too short to be unmarshalled
// returns an error (ErrTooShortToUnmarshal).
func TestScheme_UnmarshalPublicKeyWire_Error(t *testing.T) {
	sLocal := GetScheme()
	dataTooShort := []byte{1}

	_, err := sLocal.UnmarshalPublicKeyWire(dataTooShort)
	if err == nil || err != ErrTooShortToUnmarshal {
		t.Fatalf("Did not get expected error when trying to unmarshal a "+
			"public key wire format that is too short."+
			"\nexpected: %s\nreceived: %+v", ErrTooShortToUnmarshal, err)
	}
}

func TestWireLength(t *testing.T) {
	sLocal := GetScheme()
	serverPrivKey, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.Public()
	serverPubKeyBytes := serverPubKey.MarshalWire()
	wireLength := serverPubKey.GetMarshalWireLength()

	if len(serverPubKeyBytes) != wireLength {
		t.Errorf("Wire length returned is not the same as the actual "+
			"wire length, %d vs %d", wireLength, len(serverPubKeyBytes))
	}
}
