package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"golang.org/x/crypto/blake2b"
	"testing"
)

func TestMarshalUnMarshalWire(t *testing.T) {
	sLocal := GetScheme()
	serverPrivKey, err := sLocal.Generate(rand.Reader,  1024)
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

	message := []byte("fluffy bunny")
	hashed := blake2b.Sum256(message)
	signature, err := serverPrivKey.SignPSS(rand.Reader, crypto.BLAKE2b_256, hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	err = serverPubKey2.VerifyPSS(crypto.BLAKE2b_256, hashed[:], signature, nil)
	if err != nil {
		t.Fatal(err)
	}
}

