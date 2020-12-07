/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package auth

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

//Tests that the generated fingerprints do not change
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

//Tests that the first bit of the fingerprint is always zero
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

//Tests that the set fingerprints are correct
func TestSetRequestFingerprint_Consistency(t *testing.T) {
	expected := []string{
		"MY/pv2UmD7nvcsU6hmcly72humiiqOWIspbiGw4pHr4=",
		"FFx68poO2W+DyF3gR306HHjHUSXv/7/y4PlivQTC01k=",
		"bKe4HoHyxyr4kZ06JqDG6VMwbHJj7XP1cU/or7l5nYY=",
		"PLh2LmE18XPLw9J1bvkDpYEBlYS+J8TF1PaOLenRX8A=",
		"PGeHBikffOe3Z8fEnT0YGy2zk4giC8UoK9drmIJt/vk=",
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
