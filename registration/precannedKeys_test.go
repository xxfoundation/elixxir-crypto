////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"bytes"
	gorsa "crypto/rsa"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/tls"
	"math/rand"
	"strconv"
	"testing"
)

var expectedPrecanSig = []byte{62, 249, 75, 180, 81, 158, 159, 176, 51, 202, 194, 123, 150, 37, 114, 105, 157, 111, 113, 253, 139, 126, 202, 32, 7, 223, 255, 196, 95, 111, 65, 122, 174, 222, 197, 241, 20, 19, 121, 72, 157, 253, 101, 245, 78, 99, 240, 85, 67, 255, 90, 195, 73, 175, 138, 217, 180, 129, 36, 132, 141, 121, 83, 78, 80, 61, 204, 14, 45, 19, 149, 127, 90, 189, 140, 178, 234, 218, 92, 71, 114, 179, 146, 160, 217, 44, 216, 87, 201, 181, 205, 49, 11, 174, 188, 62, 134, 136, 192, 23, 101, 149, 24, 83, 97, 171, 149, 121, 72, 102, 123, 199, 162, 135, 84, 93, 8, 248, 133, 251, 57, 205, 94, 11, 73, 4, 173, 185, 239, 8, 192, 113, 24, 201, 240, 187, 159, 76, 111, 113, 202, 203, 19, 138, 227, 243, 67, 44, 237, 184, 4, 199, 78, 37, 66, 165, 116, 172, 156, 175, 106, 8, 130, 177, 151, 34, 110, 219, 143, 12, 80, 247, 226, 176, 254, 2, 199, 252, 93, 78, 41, 138, 114, 178, 239, 172, 189, 121, 253, 241, 147, 235, 127, 238, 37, 64, 182, 89, 98, 245, 49, 234, 119, 225, 202, 252, 56, 150, 144, 243, 120, 49, 109, 65, 165, 92, 196, 110, 217, 247, 212, 60, 52, 194, 69, 162, 53, 119, 218, 82, 245, 30, 148, 215, 255, 150, 108, 234, 61, 14, 191, 153, 74, 148, 240, 143, 239, 48, 5, 24, 98, 214, 120, 208, 109, 209, 127, 161, 195, 65, 161, 71, 150, 198, 197, 93, 140, 30, 42, 118, 21, 52, 250, 187, 20, 34, 7, 47, 160, 213, 30, 84, 129, 122, 184, 78, 30, 253, 31, 127, 47, 27, 139, 52, 173, 197, 203, 227, 17, 97, 92, 148, 113, 224, 105, 66, 154, 248, 217, 221, 114, 123, 4, 213, 141, 163, 103, 108, 209, 217, 148, 100, 170, 234, 175, 130, 249, 150, 69, 96, 214, 11, 169, 33, 34, 190, 199, 71, 173, 15, 143, 52, 253, 44, 57, 102, 224, 60, 173, 164, 55, 121, 39, 63, 136, 31, 67, 142, 165, 141, 231, 246, 38, 233, 195, 3, 157, 98, 77, 45, 163, 0, 53, 211, 114, 106, 181, 55, 239, 110, 149, 246, 38, 120, 190, 136, 243, 238, 185, 88, 251, 185, 191, 151, 62, 254, 226, 130, 71, 7, 191, 99, 195, 172, 33, 145, 234, 120, 247, 7, 113, 170, 202, 223, 109, 65, 129, 9, 4, 255, 42, 206, 42, 84, 200, 215, 172, 24, 36, 105, 38, 160, 133, 224, 64, 64, 24, 243, 136, 38, 240, 105, 183, 252, 182, 137, 40, 221, 11, 162, 71, 16, 244, 104, 70, 122, 31, 41, 244, 87, 153, 222, 74, 4, 186, 70, 71, 233, 246, 163, 249, 126, 65, 224, 112, 81, 48, 145, 216, 87, 97, 46, 237, 121, 162, 149, 230, 163, 152, 18, 241, 120, 228, 77, 64, 209, 126, 122, 103, 222, 173, 34, 81, 50, 250, 230, 104, 238, 160, 161, 234, 138}

// Smoke test: Ensures that precanKey is a valid RSA key.
func TestGetPrecannedKey(t *testing.T) {
	testKey := GetPrecannedKey()

	// Load key
	_, err := rsa.LoadPrivateKeyFromPem([]byte(testKey))
	if err != nil {
		t.Fatalf("Failed to load precanned private key: %v", err)
	}
}

// Smoke test: Ensure that precanCert is a valid TLS cert.
func TestGetPrecannedCert(t *testing.T) {
	testCert := GetPrecannedCert()

	// Load cert
	_, err := tls.LoadCertificate(testCert)
	if err != nil {
		t.Fatalf("Failed to load precanned cert: %v", err)
	}
}

// Smoke test: Ensure that the precanned key pair is a valid keypair.
func TestGetPrecannedKeyPair(t *testing.T) {
	testCert, testKey := GetPrecannedKeyPair()

	// Load cert
	cert, err := tls.LoadCertificate(testCert)
	if err != nil {
		t.Fatalf("Failed to load precanned cert: %v", err)
	}

	// Load key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte(testKey))
	if err != nil {
		t.Fatalf("Failed to load precanned private key: %v", err)
	}

	// Construct signature information
	prng := rand.New(rand.NewSource(42))
	opts := rsa.NewDefaultOptions()
	h := opts.Hash.New()
	data := []byte("Lorem ipsum ergo facto")
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign data using precanned key
	signedData, err := rsa.Sign(prng, privKey, opts.Hash, hashed, nil)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Pull public key from cert
	certPubKey := &rsa.PublicKey{PublicKey: *cert.PublicKey.(*gorsa.PublicKey)}

	// Test that RSA cert and key are a valid keypair
	err = rsa.Verify(certPubKey, opts.Hash, hashed, signedData, nil)
	if err != nil {
		t.Fatalf("Failed to verify signature with precanned private key. " +
			"Are the cert and key a valid keypair?")
	}

	// Tests the consistency of the signed data
	if !bytes.Equal(expectedPrecanSig, signedData) {
		t.Errorf("Consistency test failed, signature does not match expected value."+
			"\n\tExpected: %v\n\tReceived: %v", expectedPrecanSig, signedData)
	}

	s := make([]string, 0)
	for _, b := range signedData {
		s = append(s, strconv.Itoa(int(b)))
	}
}
