///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"math/rand"
	"testing"
)

// Tests that the generated MACs do not change.
func TestMAC_Consistency(t *testing.T) {
	expectedMACs := []string{
		"D7vXMT3iX/1tvFPjowoz3w5b3PbECB4EFgkR3hNzyCM=",
		"ffW26eqwyTHERUPHbmFkUitRj7c+c/PQayfwQPLihNs=",
		"flyTEnFbzEEmmMjOQhq6qr0jUYE2j22ERcR4CLH9368=",
		"PPB8eXP8BXWdxSU4a+Lp1pYVWb98COtWtR0sBngGyTs=",
		"BuvhuSO01uM+nVQPwXlOwRzr7xchVM1dRoF9h5TC2HU=",
		"PF5iYaFdhLtgOO5hWNpAF6jJaW4utF1MLGaz/gYb0TY=",
		"IpI2htMJEqZvvEKHAwWnTSqgvaAempY9//rRxNNFHQU=",
		"JpGzFglPaLzytF5gJRtSFbYoidsShEBoX1cxkAJY3F4=",
		"JdzZmlz6qdChwo7B5sChTRUpQ5zLvlH5LgndOhDHAt8=",
		"BHP2yvbUcynr6vM61qt+18YshTsyArJqv0VCq/EI3+o=",
	}
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i, expected := range expectedMACs {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		testMAC := MakeMAC(dhKey, encryptedPayload)
		testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)

		if expected != testMACBase64 {
			t.Errorf("MakeMAC() did not return the expected MAC for the given "+
				"base key and encrypted payload at index %d."+
				"\nbase key: %s\nexpected: %s\nreceived: %s",
				i, dhKey.Text(10), expected, testMACBase64)
		}
	}
}

// Tests that all generated MACs are unique.
func TestMAC_Unique(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	MACs := make(map[string]struct {
		key              *cyclic.Int
		encryptedPayload []byte
	}, 100)

	for i := 0; i < 100; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		testMAC := MakeMAC(dhKey, encryptedPayload)
		testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)

		if _, exists := MACs[testMACBase64]; exists {
			t.Errorf("Generated MAC collides with previously generated MAC."+
				"\ncurrent MAC:   dhKey: %s  encryptedPayload: %s"+
				"\npreviouse MAC: dhKey: %s  encryptedPayload: %s"+
				"\nMAC:           %s",
				dhKey.Text(10),
				base64.StdEncoding.EncodeToString(encryptedPayload),
				MACs[testMACBase64].key.Text(10),
				base64.StdEncoding.EncodeToString(MACs[testMACBase64].encryptedPayload),
				base64.StdEncoding.EncodeToString(testMAC))
		} else {
			MACs[testMACBase64] = struct {
				key              *cyclic.Int
				encryptedPayload []byte
			}{dhKey, encryptedPayload}
		}
	}
}

func TestVerifyMAC(t *testing.T) {
	expectedMACs := []string{
		"D7vXMT3iX/1tvFPjowoz3w5b3PbECB4EFgkR3hNzyCM=",
		"ffW26eqwyTHERUPHbmFkUitRj7c+c/PQayfwQPLihNs=",
		"flyTEnFbzEEmmMjOQhq6qr0jUYE2j22ERcR4CLH9368=",
		"PPB8eXP8BXWdxSU4a+Lp1pYVWb98COtWtR0sBngGyTs=",
		"BuvhuSO01uM+nVQPwXlOwRzr7xchVM1dRoF9h5TC2HU=",
		"PF5iYaFdhLtgOO5hWNpAF6jJaW4utF1MLGaz/gYb0TY=",
		"IpI2htMJEqZvvEKHAwWnTSqgvaAempY9//rRxNNFHQU=",
		"JpGzFglPaLzytF5gJRtSFbYoidsShEBoX1cxkAJY3F4=",
		"JdzZmlz6qdChwo7B5sChTRUpQ5zLvlH5LgndOhDHAt8=",
		"BHP2yvbUcynr6vM61qt+18YshTsyArJqv0VCq/EI3+o=",
	}
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i, expected := range expectedMACs {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		testMAC := MakeMAC(dhKey, encryptedPayload)
		testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)

		receivedMac, _ := base64.StdEncoding.DecodeString(expected)

		if !VerifyMAC(dhKey, encryptedPayload, receivedMac) {
			t.Errorf("VerifyMAC() failed for a correct MAC (%d)."+
				"\nbase key: %s\nexpected: %s\nreceived: %s",
				i, dhKey.Text(10), expected, testMACBase64)
		}
	}
}
