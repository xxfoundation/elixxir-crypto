////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
	"math/rand"
	"strconv"
	"testing"
	"gitlab.com/elixxir/primitives/format"
)

// Consistency test for EncryptPart.
func TestEncryptPart_Consistency(t *testing.T) {
	prng := NewPrng(42)
	// The expected values for encrypted messages and MACs
	expectedValues := []struct{ encrPart, mac string }{
		{"P5aImOP0c5OhG2g=", "Z8cPIX3zOOhqRGas2fODIozwxKuX0Gv9NdTmAwDPB9E="},
		{"zBfS1Jh3M+5IJ6s=", "Gu4DYQT7Y2cQ/6xOCgukAPUzL7ezy5ywuw3gbuzpmt0="},
		{"H7WWNFGtYZr/bmo=", "baDwObK6aukr1egK0R8/U3Zicsx5PvHFdCwaC5c19UY="},
		{"MSLjaczLmqrm8AE=", "UiqMNzA8oNowFx/91ne5G8lWs/Pr3Un/sP180W2HP0k="},
		{"moiunm7hg6Wyag4=", "XSpK/MKKTC2kZQXKPiWmthpQOiOcgCdzfjvTO3+NECQ="},
		{"wHmh9im367tJ9yQ=", "MIdJibyECF1veMZmql62xCNQEaKzgcuJtOBjhewExNA="},
		{"lJ1IKBOeo6Q/mrI=", "GK/0dPDvHj7VmWzveLDcsk12Wj4JY+JZkZjyP7GGT/4="},
		{"ylcp4jK3CxeqerQ=", "NB+iYXJVU5uX1BikekC62OtM48QllxyHAscdcEiFbAs="},
		{"k9hB2wqt7P6NrY0=", "KobYc8cu7WHL+uxAenvijFe1fdecCwTx4/OBzTSCvM4="},
		{"fmK35rHs7Nj8wfc=", "SFT2NuDirNGWLiG5K22mF4+7ONcnSb7U4nj2X/OG2MY="},
	}

	kwy, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	for i, expected := range expectedValues {
		payload := []byte("payloadMsg" + strconv.Itoa(i))
		fpBytes := make([]byte, format.KeyFPLen)
		prng.Read(fpBytes)
		fp := format.NewFingerprint(fpBytes)
		ecr, mac, err := EncryptPart(kwy, payload, uint16(i), fp)
		if err != nil {
			t.Errorf("EncryptPart returned an error (%d): %+v", i, err)
		}

		// Verify the encrypted part
		ecr64 := base64.StdEncoding.EncodeToString(ecr)
		if expected.encrPart != ecr64 {
			t.Errorf("Encrypted part does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected.encrPart, ecr64)
		}

		// Verify the MAC
		mac64 := base64.StdEncoding.EncodeToString(mac)
		if expected.mac != mac64 {
			t.Errorf("MAC does not match expected (%d)"+
				"\nexpected: %s\nreceived: %s", i, expected.mac, mac64)
		}
	}
}

// Tests that a file part encrypted with EncryptPart can be decrypted with
// DecryptPart. This ensures that they are the inverse of each other.
func TestEncryptPart_DecryptPart(t *testing.T) {
	prng := NewPrng(42)
	key, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	for i := uint16(0); i < 25; i++ {
		message := make([]byte, 32)
		_, _ = prng.Read(message)
		fpBytes := make([]byte, format.KeyFPLen)
		prng.Read(fpBytes)
		fp := format.NewFingerprint(fpBytes)
		ecr, mac, err := EncryptPart(key, message, uint16(i), fp)
		if err != nil {
			t.Errorf("Failed to encrypt part %d: %+v", i, err)
		}

		dec, err := DecryptPart(key, ecr, mac, uint16(i), fp)
		if err != nil {
			t.Errorf("Failed to decrypt part: %+v", err)
		}

		if !bytes.Equal(dec, message) {
			t.Errorf("Decrypted message does not match original message (%d)."+
				"\nexpected: %+v\nreceived: %+v", i, message, dec)
		}
	}
}

// Error path: tests DecryptPart returns the expected error if the provided MAC
// is incorrect.
func TestEncryptPart_DecryptPart_InvalidMacError(t *testing.T) {
	prng := NewPrng(42)
	key, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	for i := uint16(0); i < 25; i++ {
		message := make([]byte, 32)
		_, _ = prng.Read(message)
		fpBytes := make([]byte, format.KeyFPLen)
		prng.Read(fpBytes)
		fp := format.NewFingerprint(fpBytes)
		ecr, mac, err := EncryptPart(key, message, i, fp)
		if err != nil {
			t.Errorf("Failed to encrypt part %d: %+v", i, err)
		}

		// Generate invalid MAC
		_, _ = prng.Read(mac)

		_, err = DecryptPart(key, ecr, mac, i, fp)
		if err == nil || err.Error() != macMismatchErr {
			t.Errorf("DecryptPart did not return the expected error when the "+
				"MAC is invalid.\nexpected: %s\nreceived: %+v",
				macMismatchErr, err)
		}
	}
}

// Prng is a PRNG that satisfies the csprng.Source interface.
type Prng struct{ prng io.Reader }

func NewPrng(seed int64) csprng.Source     { return &Prng{rand.New(rand.NewSource(seed))} }
func (s *Prng) Read(b []byte) (int, error) { return s.prng.Read(b) }
func (s *Prng) SetSeed([]byte) error       { return nil }
