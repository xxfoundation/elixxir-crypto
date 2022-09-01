////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                                         //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"fmt"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"reflect"
	"testing"
)

// Expected (pre-canned) input and output
var (
	Usernames = []string{
		"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGQ==",
		"GhscHR4fICEiIyQlJicoKSorLC0uLzAxMg==",
		"MzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKSw==",
	}

	ReceptionKeys = []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCheF8LRTgCWMO3w3k1gXs1AU/x65Bgs1DV67PdM8Ik8NTV0eTw\nIEGXNbYxm/1tyMzbuOPkhF7h5bsj3V7TWwWa95zPbpgdt1Qpz2uvtLxAf9YWPCIz\nByp+dzQJOLRrFK21eKtDjkgfJbc+31701F/V/EzWKxRA2rDtCWKSCrMIRwIDAQAB\nAoGBAIdLdc/auth0ieGzHx+vE45RQCxDpiDwfv4P1hC1qqoLRTq3+W0eifbqIXQl\n8U6I3uYIYKN8Koh7VrfxZ+AOt31Rnr5EUfYqE84C8EZwT6jtU9gIMg2f54bnNKkk\n4lEdIP2q/rpwSuRa6k7XD6SjNyTLUJc30OQVtUxNmHaA0tYRAkEA00xZSiyAa9+k\n51bkWLSLrkkNBC4Ho1XpbPuJzKvygZ15TZ4Sgv0KclTxs5T26rxmpki639tH01CK\naTgLpg1f+QJBAMOhZcm3jNjpdCS8cwEJzZZfovWMi5DI2ou1Ie3oSPz48LvUjBdg\nHMfdiSiuk5WQ/gfTFFKG+yumLJScPPF6Oj8CQEIzWIJRwQaLMko8whw8rMq1Hnvh\nxAjboN/BS2IxuS/824WC8f/SMdSyYmvGTzoqPur4PHxoYm+Fe2gN5DBpXlkCQCRX\nAN99ty47/5UrZHmW5pe+YDkYyHw2s1IsbYcSFSzY2W8qxnM5KV9/KZFjDItGCcpO\nTYIfDN1I2xMoCrIYsGUCQQCpx9ojdsUvxywFsm/AAEZBwTSiE15Y1HVI8fnQwuK7\nGbBiAK/KoW+RTb1Ik7QJ5k8lzCgLI1JAXzxLpdp8/GZO\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCnfGhO0O/3sH/S0x73YorXGt4LdWXw9BP0AAdNYnrDf8DZgczy\nwVlkWj4MvDYik2ITtC2RuFMSuixvudwkMUwfH1pUJq1ZrKFg6chtwOTZmhCTbsRZ\nXyWvJ81ugi8+cb5S1W/cSwWe5s9hXYhILkeCM+SngBJ3evdZqgAlJxKqzwIDAQAB\nAoGATg2OVtzMWHQqvceh8Mw9xA1DWbe2cFpvShERViEE8UMCTttM9fzhegEMVccI\nu4hP9rrLWdO680lMGC1XyI4o2L7hddCflnNuzdwVnqSpDL0ZYAggEWJu//1vdv9p\n1i59gmc4uBHLuL8nJBPEeCcGTitxoAD4Qrkuku3evYuJ74ECQQDDT8EJpn67eOhf\nYdZn9xbtcXoGVYPLSLWAm3kt2NCNHsDUFxL/+XeQddcOdBAHgloPgqlUp5GcPGOQ\n5dCEvzPhAkEA24c9wFyK9BCBKqIuL4qf1n8avIk9yz9gCvG/1Cvej1CfQmGGs/lO\nfX6CyoXlNVnO5MymFm1UzQAG+blKNGS0rwJAarhPgFhrc0CzqDqrjw9ihce1p3Re\nmVtXYbiSVEzeV93v+3PIO/oyLMtXAVzFzXSahVMd91XAqKAOv4PzljVrwQJATiJ+\nqh7GHkRZlPEQez9d0JyAyaYXZmXyKzMMUdojZuMNLDVGGnyboTMMHkU15Z1HdEwa\nuVTEoApocS2v6aIGZQJBAKzHcE9HUrh7AqxrIR/vD8ekl6iP56K6IWRzSOWjQHlQ\nb+xuX1qrDkWgcJv2JpXaOirrKk+8T7v7pxFp6ERKC64=\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC8lFHNs6pvBDDo9DK3NL3JuRohLwRblPWXmiTj+/o1RvwitYua\nVfNmnp5gI4Tm1b85pQMMJv6brN6uwY3wK94P2sz7WDIPWntNofJIBMsoBohCKZ9d\n9teqk1w9nwTmgE40gFK3koc3g6Bo6SZEDmqhwIKL+JmxQPSy6BOrRTkQfwIDAQAB\nAoGAT31RshyepeclWry8t/8SVPqiagRwmM4Ea9/81uD7CgQe+d5+txKt477O0YWH\nWuoUjg7hZvj079gBkbZixy8mjdwIB3JQgg+iwLpXF5jckznLMUhENWgUvF+Fkv/+\nIwZSxHifeEByfKkXxAwNEn/bG/WR2i+CxN/xwJEJAKwxU/kCQQD0jeKWfjtngGxF\nuLW5/TLWt3QvHIABzs2QIb1EegB7M3iA7g1pX8YpchQlLyyumwwo7auGJ6TzC7Hi\n1PpsplzNAkEAxWfGNmubYdoLSHzn5EExE2Y0ufizFeJ8DyfVNx95xKnysApsksDr\n2zEXZF21Z4/K0LbS7FWYSzeJbEduqNRiewJAGYzFUpHHpQ2ewj4FBnR0nkg2ZEGn\nAglYIqnTu1a/vB9phJbaYdr2uhfIEQZ3tZpPT+tc0zxLGHVtVVSJAVb0NQJAP/4V\nDj0x4LWrZLNBBQhxHUXLn+HURCroZo1WHAlzEuK4zoKCkcxCaQrv91Q9YzYE3EX3\n+C8DMJbvUI+Tet1mkwJAamSH6SvLm2CrchvUVtO48YwKgzhX9zRISsuotvidMcsA\n7SDQ026qBrTnqBWosng2PZ12kG3nbsrfzFfI5irzlA==\n-----END RSA PRIVATE KEY-----",
	}

	ExpectedVerificationSignatures = []string{
		"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",
	}
)

// Unit test: Tests that the signature from SignVerification
// will not fail if passed into VerifyVerificationSignature with the
// same data passed in.
func TestSignVerifyVerification(t *testing.T) {

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Load private key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([]*rsa.PublicKey, numTests)
	for i := 0; i < numTests; i++ {
		priv, err := rsa.LoadPrivateKeyFromPem([]byte(ReceptionKeys[i]))
		if err!=nil{
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}
		receptionKeys[i] = priv.GetPublic()
	}

	// Sign and verify
	for i := 0; i < numTests; i++ {
		// Sign data
		sig, err := SignVerification(notRand, privKey,
			Usernames[i], receptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}

		// Use signature provided above and verify
		err = VerifyVerificationSignature(privKey.GetPublic(),
			hashUsername(Usernames[i]), receptionKeys[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature for test %d/%v: %v", i, numTests, err)
		}
	}

}


// Unit test: Generate signatures using pre-canned data
// and compare it against the expected pre-canned data.
func TestSignVerification_Consistency(t *testing.T) {

	// Load private key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([]*rsa.PublicKey, numTests)
	for i := 0; i < numTests; i++ {
		priv, err := rsa.LoadPrivateKeyFromPem([]byte(ReceptionKeys[i]))
		if err!=nil{
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}
		receptionKeys[i] = priv.GetPublic()
	}

	// Generate signatures
	signatures := make([]string, numTests)
	for i := 0; i < numTests; i++ {
		// Sign data
		notRand := &CountingReader{count: uint8(0)}
		sig, err := SignVerification(notRand, privKey,
			Usernames[i], receptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}
		signatures[i] = base64.StdEncoding.EncodeToString(sig)
		fmt.Println(signatures[i])

	}

	// Check generated output is consisted with precanned output
	if !reflect.DeepEqual(ExpectedVerificationSignatures, signatures) {
		t.Errorf("Generated data does not match pre-canned data."+
			"\nExpected: %v"+
			"\nReceived: %v", ExpectedVerificationSignatures, signatures)
	}

}
