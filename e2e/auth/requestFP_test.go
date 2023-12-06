////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

// Tests that the generated fingerprints do not change
func TestMakeRequestFingerprint_Consistency(t *testing.T) {
	expected := []string{
		"MY/pv2UmD7nvcsU6hmcly72humiiqOWIspbiGw4pHr4=",
		"PL2EufLks2RRfSWWY4lCz14k7g/Pj1rXz/W1CEqrv4s=",
		"Z5ylMk3gWI010LdHaziE5y8B1JjJjnYIj8GAy+mudk4=",
		"Atjw2OmNr/s4TvAiL9v3DSZyoFeRQxRku7FpCsSZXLw=",
		"D4n4ammObGofQuAUcDaR4avOgkB8dB26vfRR0LhLSLE=",
	}

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(expected); i++ {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, grp)

		desig := MakeRequestFingerprint(pubKey)
		desigBase64 := base64.StdEncoding.EncodeToString(desig[:])
		if expected[i] != desigBase64 {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, desigBase64, expected[i])
		}
	}
}

// Tests that the first bit of the fingerprint is always zero
func TestMakeRequestFingerprint_FirstBitZero(t *testing.T) {
	const numTests = 100

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < numTests; i++ {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, grp)

		fp := MakeRequestFingerprint(pubKey)
		if fp[0]&0b10000000 != 0 {
			t.Errorf("first bit on fingperprint at index %v is not zero\n"+
				"\tfingerprint: %v", i, fp)
		}
	}
}

// Tests that the set fingerprints are correct
func TestSetRequestFingerprint_Consistency(t *testing.T) {
	expected := []string{
		"MY/pv2UmD7nvcsU6hmcly72humiiqOWIspbiGw4pHr4=",
		"FT9Me9dXBKq3ZgbalumlDpBK8/KsgOZukFbDih03wro=",
		"U+C5q0c2SmYzteqVlMLWnlB5BycOwja8p7Ttfw6EVNQ=",
		"A1VhcJrrQswb4nFu7GrzoJLKZWySYZAxG+4NHUzfJuE=",
		"FhuLR6vRFoy0kAC8ow1G82D4Ofu1ddAmAKKDvqlWf+M=",
	}

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(expected); i++ {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, grp)

		msg := format.NewMessage(grp.GetP().ByteLen())

		messageContents := make([]byte, msg.ContentsSize())
		prng.Read(messageContents)
		msg.SetContents(messageContents)
		SetRequestFingerprint(msg, pubKey)

		receivedFP := msg.GetKeyFP()
		fpBase64 := base64.StdEncoding.EncodeToString(receivedFP[:])

		if expected[i] != fpBase64 {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, fpBase64, expected[i])
		}
	}
}
