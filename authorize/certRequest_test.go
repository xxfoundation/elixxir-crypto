package authorize

import (
	"bytes"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

func TestSignVerify_CertRequest(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	token := "acme-test-token"
	timestamp, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("Failed to parse timestamp for SignVerify consistency test: %+v", err)
	}
	testDelta := 24 * time.Hour
	testNow := timestamp.Add(testDelta / 2)
	sig, err := SignCertRequest(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token")
	}

	err = VerifyCertRequest(pk.GetPublic(), sig, token, testNow, timestamp, testDelta)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}

func TestSignVerify_CertRequest_Consistency(t *testing.T) {
	rng := &CountingReader{count: uint8(0)}
	pk, err := rsa.GenerateKey(rng, 1024)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	token := "acme-test-token"
	timestamp, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("Failed to parse timestamp for SignVerify consistency test: %+v", err)
	}
	testDelta := 24 * time.Hour
	testNow := timestamp.Add(testDelta / 2)
	expectedSig := []byte{89, 26, 164, 145, 177, 46, 37, 168, 171, 201, 60, 55, 95, 70, 1, 62, 99, 103, 130, 108, 125, 26, 201, 245, 10, 136, 78, 77, 16, 78, 228, 149, 109, 92, 48, 252, 41, 36, 188, 184, 100, 118, 249, 84, 215, 138, 249, 170, 252, 113, 198, 64, 191, 195, 85, 87, 125, 204, 171, 111, 51, 248, 224, 216, 222, 104, 98, 230, 42, 145, 124, 21, 36, 63, 217, 38, 84, 84, 97, 57, 39, 36, 138, 2, 80, 149, 194, 73, 15, 10, 171, 54, 223, 215, 167, 119, 250, 106, 86, 220, 125, 116, 43, 152, 89, 21, 251, 62, 35, 168, 216, 197, 57, 52, 161, 244, 177, 160, 184, 24, 88, 5, 42, 101, 16, 67, 136, 62}
	sig, err := SignCertRequest(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token: %+v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignACMEToken\n\tExpected: %+v\n\tReceived: %+v", expectedSig, sig)
	}

	err = VerifyCertRequest(pk.GetPublic(), sig, token, testNow, timestamp, testDelta)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}
