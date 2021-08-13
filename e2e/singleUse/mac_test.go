///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/xx_network/crypto/large"
	"math/rand"
	"testing"
)

// Tests that the generated MACs do not change.
func TestMAC_Consistency(t *testing.T) {
	expectedMacs := []string{
		"P5Arek8yIlKVmM4IHJTOycUph0RLeiP0emA0DCx4z90=",
		"P9LcMFLn+q8/6SOSb9rrYpLyn3X5MMuephBSOtIF4M0=",
		"UOPiUuATfn9C/KjmFZdA4zTfIykMb0HIgELKLbixrtk=",
		"UYUHQLjbyDBdZn/MTNQBgrvUQPN0MnVpdYEI0iB/Q68=",
		"fArOwzcunIaDYoIgtViaoBOkL2/v95Hm+6KRTEE6F9A=",
		"XMhNPEyxy8q0p+bsjGHPQL5vzA+HyqUoooHXrTBEYF4=",
		"IDJ4iTo9IcNB/oR5RP45de53SxuWsSSKlYcmGInQtoU=",
		"Z4QqQfBp0ezUzAU2MHBUR9K0Bdl9Z3WF5Rcy553fb+8=",
		"HthTNmjJ78iCdjMX+zSyhabsiCEE8QmH/AsDFfH8yUA=",
		"GnE0KJAwk594cKLt6i2kHAqMJZ8DnXv7XyrByU27F/g=",
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
		"P5Arek8yIlKVmM4IHJTOycUph0RLeiP0emA0DCx4z90=",
		"P9LcMFLn+q8/6SOSb9rrYpLyn3X5MMuephBSOtIF4M0=",
		"UOPiUuATfn9C/KjmFZdA4zTfIykMb0HIgELKLbixrtk=",
		"UYUHQLjbyDBdZn/MTNQBgrvUQPN0MnVpdYEI0iB/Q68=",
		"fArOwzcunIaDYoIgtViaoBOkL2/v95Hm+6KRTEE6F9A=",
		"XMhNPEyxy8q0p+bsjGHPQL5vzA+HyqUoooHXrTBEYF4=",
		"IDJ4iTo9IcNB/oR5RP45de53SxuWsSSKlYcmGInQtoU=",
		"Z4QqQfBp0ezUzAU2MHBUR9K0Bdl9Z3WF5Rcy553fb+8=",
		"HthTNmjJ78iCdjMX+zSyhabsiCEE8QmH/AsDFfH8yUA=",
		"GnE0KJAwk594cKLt6i2kHAqMJZ8DnXv7XyrByU27F/g=",
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
