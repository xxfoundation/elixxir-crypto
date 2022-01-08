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
	"gitlab.com/xx_network/crypto/large"
	"math/rand"
	"testing"
)

// Tests that the generated MACs do not change.
func TestMAC_Consistency(t *testing.T) {
	expectedMacs := []string{
		"MS9siixMT9/wskcdoQhmuLXCD7wK3h6yf0cWF3ZodTQ=",
		"XLCWSXRdRlDyBZ8Wy0soO0MB0XgOUdhRX9HAd5RDUVk=",
		"fM67dZ5G4ce2CF2MneYH29izP4OsKv5k0wQuyjLlLuk=",
		"LBK5gesIs8sOUU9slTh8VGOZKKrTHXtXLmmLgKP25J0=",
		"G5Nm5GbKiLT0tfJkYWYkgFEY8IxVQHJATj0TfVi9i0k=",
		"PPvlpHWQN5Ear436vPcgpbjLNkH9ZK/ZgrW6xwbNbvM=",
		"CnlszFIGBZnuHfipIAvQa5aprg2bUD27EkmI2wzJ9G4=",
		"XanqEhRX6MMmFNyJA8qGiOzn4pvof72uQE5NoM096OM=",
		"XqK6aJspygyh6z4e5wXQo/TkSvBy1rJtMVlv+OAFUm4=",
		"TqiTyffLDLclCmRiCH2TeKQk5Lx/Z8SSdAU9s+sHl2g=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedMac := range expectedMacs {
		key := make([]byte, prng.Intn(255))
		prng.Read(key)
		encryptedPayload := make([]byte, prng.Intn(500))
		prng.Read(encryptedPayload)
		testMAC := MakeMAC(key, encryptedPayload)
		testMacBase64 := base64.StdEncoding.EncodeToString(testMAC)

		if expectedMac != testMacBase64 {
			t.Errorf("MakeMAC() did not return the expected MAC (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedMac, testMacBase64)
		}
	}
}

// Tests that all generated MACs are unique.
func TestMAC_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	MACs := make(map[string]struct {
		key              []byte
		encryptedPayload []byte
	})

	// Test with same key but differing payloads
	for i := 0; i < testRuns; i++ {
		key := make([]byte, prng.Intn(32)+i)
		prng.Read(key)
		for j := 0; j < testRuns; j++ {
			encryptedPayload := make([]byte, prng.Intn(500)+j)
			prng.Read(encryptedPayload)

			testMAC := MakeMAC(key, encryptedPayload)
			testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)

			if _, exists := MACs[testMACBase64]; exists {
				t.Errorf("Generated MAC collides with previously generated MAC (%d, %d)."+
					"\ncurrent MAC:   key: %+v  encryptedPayload: %+v"+
					"\npreviouse MAC: key: %+v  encryptedPayload: %+v"+
					"\nMAC:           %s", i, j,
					key, encryptedPayload, MACs[testMACBase64].key,
					MACs[testMACBase64].encryptedPayload, testMAC)
			} else {
				MACs[testMACBase64] = struct {
					key              []byte
					encryptedPayload []byte
				}{key, encryptedPayload}
			}
		}
	}

	// Test with same payload but differing keys
	for i := 0; i < testRuns; i++ {
		encryptedPayload := make([]byte, prng.Intn(500)+i)
		prng.Read(encryptedPayload)
		for j := 0; j < testRuns; j++ {
			key := make([]byte, prng.Intn(32)+j)
			prng.Read(key)

			testMAC := MakeMAC(key, encryptedPayload)
			testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)

			if _, exists := MACs[testMACBase64]; exists {
				t.Errorf("Generated MAC collides with previously generated MAC (%d, %d)."+
					"\ncurrent MAC:   key: %+v  encryptedPayload: %+v"+
					"\npreviouse MAC: key: %+v  encryptedPayload: %+v"+
					"\nMAC:           %s", i, j,
					key, encryptedPayload, MACs[testMACBase64].key,
					MACs[testMACBase64].encryptedPayload, testMAC)
			} else {
				MACs[testMACBase64] = struct {
					key              []byte
					encryptedPayload []byte
				}{key, encryptedPayload}
			}
		}
	}
}

// Happy path.
func TestVerifyMAC(t *testing.T) {
	expectedMACs := []string{
		"MS9siixMT9/wskcdoQhmuLXCD7wK3h6yf0cWF3ZodTQ=",
		"XLCWSXRdRlDyBZ8Wy0soO0MB0XgOUdhRX9HAd5RDUVk=",
		"fM67dZ5G4ce2CF2MneYH29izP4OsKv5k0wQuyjLlLuk=",
		"LBK5gesIs8sOUU9slTh8VGOZKKrTHXtXLmmLgKP25J0=",
		"G5Nm5GbKiLT0tfJkYWYkgFEY8IxVQHJATj0TfVi9i0k=",
		"PPvlpHWQN5Ear436vPcgpbjLNkH9ZK/ZgrW6xwbNbvM=",
		"CnlszFIGBZnuHfipIAvQa5aprg2bUD27EkmI2wzJ9G4=",
		"XanqEhRX6MMmFNyJA8qGiOzn4pvof72uQE5NoM096OM=",
		"XqK6aJspygyh6z4e5wXQo/TkSvBy1rJtMVlv+OAFUm4=",
		"TqiTyffLDLclCmRiCH2TeKQk5Lx/Z8SSdAU9s+sHl2g=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expected := range expectedMACs {
		key := make([]byte, prng.Intn(255))
		prng.Read(key)
		encryptedPayload := make([]byte, prng.Intn(500))
		prng.Read(encryptedPayload)

		testMAC := MakeMAC(key, encryptedPayload)
		testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)
		receivedMac, _ := base64.StdEncoding.DecodeString(expected)

		if !VerifyMAC(key, encryptedPayload, receivedMac) {
			t.Errorf("VerifyMAC() failed for a correct MAC (%d)."+
				"\nkey: %+v\nexpected: %s\nreceived: %s",
				i, key, expected, testMACBase64)
		}
	}
}

// Error path: tests that bad MACs are not verified.
func TestVerifyMAC_InvalidMacError(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < 100; i++ {
		key := make([]byte, prng.Intn(255))
		prng.Read(key)
		encryptedPayload := make([]byte, prng.Intn(500))
		prng.Read(encryptedPayload)
		expectedMac := make([]byte, prng.Intn(255))
		prng.Read(expectedMac)

		testMAC := MakeMAC(key, encryptedPayload)
		testMACBase64 := base64.StdEncoding.EncodeToString(testMAC)
		expectedMACBase64 := base64.StdEncoding.EncodeToString(expectedMac)

		if VerifyMAC(key, encryptedPayload, expectedMac) {
			t.Errorf("VerifyMAC() verified invalid MAC (%d)."+
				"\nkey: %+v\nexpected: %s\nreceived: %s",
				i, key, expectedMACBase64, testMACBase64)
		}
	}
}

// getGrp returns a cyclic Group for testing.
func getGrp() *cyclic.Group {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088" +
		"A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1" +
		"4374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDE" +
		"E386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4" +
		"8361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077" +
		"096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8" +
		"6039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE51" +
		"5D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}
