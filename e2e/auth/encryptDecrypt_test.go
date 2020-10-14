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
		"4hsxVHFT1hBlrn6HYyas",
		"vsitOqh5clZF3F/v5Hqq",
		"vju+iXTG/QShVaV/G6lQ",
		"GcwqYRjYnI1Mz0FDnk6g",
		"42xrxH2LglZpXDrzNc0i",
	}
	expectedMac := []string{
		"H/8GiORzJ6RBSNCwIdJq1TNnvRuPJx5eKCzeE7H+rSM=",
		"UV+CHvaqK9vqTCGIBwbFtCEixJCbPRN5zXRDPLnQN0Y=",
		"8vS1lGArSQTvxhbuq6OhPpOjrdyLwHB0QAHFKlHScCE=",
		"f/cMqLA57UR5yOScT2I4w8F3nB0Seqk2lrSqriAIW8E=",
		"tbpFyrG4DBA+TJ4Dz3vMyx6SeZ7/JWbKHxFu7mwSE3Q=",
	}
	expectedFingerprints := []string{
		"r3zSknIZqSD3xIV3JuER1PH7rne/ghcVdtSLTHMwEx8=",
		"rtoXXxA36jkhK4jw0LjCLdfU1s6mCHGvT3SUWwf373o=",
		"N8hJqAM9SjML62SluMOqdK2XhzdLBlzujj9tLilc+xo=",
		"iCPkm0Tc51YpwwgbYwgiWu2OedpJlbAyv1bJRvwkNHE=",
		"Dco4onqYu2NCqUMuVuFge6w8/Kc4Mnb/+/geXrYyHDg=",
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
		ecr, mac, fpVector := AuthPayloadEncrypt(myPrivKey, parnterPubKey, testVector, testSalt, payload, grp)

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
		ok, decrypted, decFPVector := AuthPayloadDecrypt(myPrivKey,
			parnterPubKey, testVector, testSalt, ecr, mac, grp)

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
	ecr, mac, _ := AuthPayloadEncrypt(myPrivKey, theirPubKey, testVector, testSalt, payload, grp)
	ok, dec, _ := AuthPayloadDecrypt(myPrivKey, theirPubKey, testVector, testSalt, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}

	ecr, mac, _ = AuthPayloadEncrypt(theirPrivKey, myPubKey, testVector, testSalt, payload, grp)
	ok, dec, _ = AuthPayloadDecrypt(theirPrivKey, myPubKey, testVector, testSalt, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}
}
