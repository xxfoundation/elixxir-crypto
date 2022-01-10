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
		"99KCYpcHb7O2RsVF/zRz",
		"O5eNOVs9BAcEi4leA5P9",
		"zXrMJJ1fHxO9i0zKHv9a",
		"aRTXHn0au6WM+nypLSrq",
		"/q/m4sI3ImXrw6mBGu4C",
	}
	expectedMac := []string{
		"SIaOcC2qec+e2ow3Vxw4gFp/MikAhS3otVxj00TCYII=",
		"e8UN1yfN4Zs2ws2xFWKnZQ3TQUn0zkwmr7p1Ofa5h/0=",
		"B914VCyWYyGGK2yX55BNBRDko468GxN1gqVXVglHIco=",
		"Wl99M0Dx/65/lx8yQ9RDLSKPEqq0H37nNmBtewo3zFc=",
		"Fb4oIsCZjXHpvxIdzFfo70HsSGR2Pn/ysuA2RLvG3hc=",
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
		// Generate the paylod, vector
		payload := []byte("payloadMessage" + strconv.Itoa(i))
		testVector := make([]byte, NonceLength)
		copy(testVector[:], "test"+strconv.Itoa(i))

		// Generate the keys
		myPrivKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		parnterPubKey := diffieHellman.GeneratePublicKey(
			diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)

		// Run the encryption
		ecr, mac := Encrypt(myPrivKey, parnterPubKey, payload, grp)

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

		// Run the decryption
		ok, decrypted := Decrypt(myPrivKey, parnterPubKey, ecr, mac, grp)

		if !ok {
			t.Errorf("Did not pass a successful MAC check on decryption at index %d", i)

		}

		// Check if the decrypted message matches the original payload
		if !bytes.Equal(payload, decrypted) {
			t.Errorf("received and expected do not match at index %v for decrypted\n"+
				"\treceived: %s\n\texpected: %s", i, decrypted, payload)

		}

	}

}

// Test encrypt/decrypt against two different keys
func TestAuthPayloadEncryptDecrypt(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	testVector := make([]byte, NonceLength)
	copy(testVector[:], "test")
	payload := []byte("payloadMessage")

	// Generate the keys
	myPrivKey := diffieHellman.GeneratePrivateKey(
		diffieHellman.DefaultPrivateKeyLength, grp, prng)
	myPubKey := diffieHellman.GeneratePublicKey(myPrivKey, grp)
	theirPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	theirPubKey := diffieHellman.GeneratePublicKey(theirPrivKey, grp)

	// Run the encryption
	ecr, mac := Encrypt(myPrivKey, theirPubKey, payload, grp)
	ok, dec := Decrypt(myPrivKey, theirPubKey, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}

	ecr, mac = Encrypt(theirPrivKey, myPubKey, payload, grp)
	ok, dec = Decrypt(theirPrivKey, myPubKey, ecr, mac, grp)
	if !ok {
		t.Errorf("Could not verify MAC")
	}

	if !bytes.Equal(dec, payload) {
		t.Errorf("Decrypted does not match original payload\n"+
			"\treceived: %v\n\texpected: %v", dec, payload)
	}
}
