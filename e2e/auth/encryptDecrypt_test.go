////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"math/rand"
	"strconv"
	"testing"
)

func TestPayloadEncryptDecrypt_Consistency(t *testing.T) {

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	// The expected values for encrypted messages, MACs and fingerprints
	expectedEncrypted := []string{
		"p3gclxUyLgEJnds12f+S",
		"zwKMLOdjcLmGozAkvs+o",
		"t0IclvgIS1GQM6Mnu7kR",
		"tt1AcInPKOjk54fWTj8S",
		"1MUXQRgAN6gC0lzR5IKF",
	}
	expectedMac := []string{
		"6n6Cjkv4KlTW5Syd+WQBhZ0kPJIYz/E9AYyQkxcYw8E=",
		"3eSYrf8mQ61MQVaJT5Zz4ho4T30a40AZmooJcb/dsas=",
		"GhzKIclJAP2LKVWgrH9WCinDIKIQqVYr1Omlo99VMDM=",
		"evoeLwK5mxPZtLHV22WDOc8ih/bqREBzCOuabrHZ/1U=",
		"CexuXGkx23NzPre5Nnbnma739984Lb1ocq4bsXheNTs=",
	}
	expectedFingerprints := []string{
		"4juO1SAC6IG67PVQvuf+t1CtLP7r752Ul6hPk0J4jyM=",
		"Pp1b0l99KdGrg4M282Ydo+3WfNLvKa0aQfbW/eVk/wY=",
		"YxMq2etN6rBjbbfd6TLgxZ/UxxyOcUDO8jNjGjTyNz0=",
		"bGF5Cf1x2oPr+uCTT/Qzy2f2n7gYTDpMyg2XPTsuIyU=",
		"akQWCbPsJgbvLjWwd8VeD2OsFc+SyrCYOcfoPMBKLvo=",
	}

	// Encrypt/Decrypt 5 messages
	for i := 0; i < len(expectedFingerprints); i++ {
		// Generate the paylod, vector and salt
		payload := []byte("payloadMessage" + strconv.Itoa(i))
		testVector := make([]byte, NonceLength)
		copy(testVector[:], "test"+strconv.Itoa(i))
		testSalt := []byte("salt" + strconv.Itoa(i))

		// Generate the keys
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		parnterPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)

		// Run the encryption
		ecr, mac, fpVector := Encrypt(myPrivKey, parnterPubKey, testSalt, payload, grp)

		// Check if the encrypted message is consistent
		ecr64 := base64.StdEncoding.EncodeToString(ecr)
		if expectedEncrypted[i] != ecr64 {
			t.Errorf("received and expected do not match at index %v for Encrypted\n"+
				"\treceived: %s\n\texpected: %s", i, ecr64, expectedEncrypted[i])
		}

		// Check if the MAC is consistent
		mac64 := base64.StdEncoding.EncodeToString(mac)
		if expectedMac[i] != mac64 {
			t.Errorf("received and expected do not match at index %v for MAC\n"+
				"\treceived: %s\n\texpected: %s", i, mac64, expectedMac[i])
		}

		// Check if the fingerprint is consistent
		fp64 := base64.StdEncoding.EncodeToString(fpVector[:])
		if expectedFingerprints[i] != fp64 {
			t.Errorf("received and expected do not match at index %v for fingerprints\n"+
				"\treceived: %s\n\texpected: %s", i, fp64, expectedFingerprints[i])
		}

		// Run the decryption
		ok, decrypted, decFPVector := Decrypt(myPrivKey, parnterPubKey, testSalt, ecr, mac, grp)

		if !ok {
			t.Errorf("Did not pass a successful MAC check on decryption at index %d", i)

		}

		// Check if the decrypted message matches the original payload
		if !bytes.Equal(payload, decrypted) {
			t.Errorf("received and expected do not match at index %v for decrypted\n"+
				"\treceived: %s\n\texpected: %s", i, decrypted, payload)

		}

		// Check if the fingerprint is consistent
		decFP64 := base64.StdEncoding.EncodeToString(decFPVector[:])
		if expectedFingerprints[i] != decFP64 {
			t.Errorf("received and expected do not match at index %v for fingerprints\n"+
				"\treceived: %s\n\texpected: %s", i, decFP64, expectedFingerprints[i])
		}

	}

}

// Test encrypt/decrypt against two different keys
func TestAuthPayloadEncryptDecrypt(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	testVector := make([]byte, NonceLength)
	copy(testVector[:], "test")
	testSalt := []byte("salt")
	payload := []byte("payloadMessage")

	// Generate the keys
	myPrivKey := diffieHellman.GeneratePrivateKey(
		diffieHellman.DefaultPrivateKeyLength, grp, prng)
	myPubKey := diffieHellman.GeneratePublicKey(myPrivKey, grp)
	theirPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	theirPubKey := diffieHellman.GeneratePublicKey(theirPrivKey, grp)

	// Run the encryption
	ecr, mac, _ := Encrypt(myPrivKey, theirPubKey, testSalt, payload, grp)
	ok, dec, _ := Decrypt(myPrivKey, theirPubKey, testSalt, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}

	ecr, mac, _ = Encrypt(theirPrivKey, myPubKey, testSalt, payload, grp)
	ok, dec, _ = Decrypt(theirPrivKey, myPubKey, testSalt, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}
}
