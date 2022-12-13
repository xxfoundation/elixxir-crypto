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
	expectedSig := []byte{90, 93, 43, 229, 9, 238, 206, 159, 151, 106, 94, 134, 24, 13, 254, 30, 218, 171, 122, 232, 62, 136, 217, 225, 177, 42, 194, 11, 230, 177, 3, 115, 187, 182, 115, 25, 151, 138, 11, 205, 247, 86, 4, 180, 23, 59, 212, 72, 100, 10, 71, 233, 73, 142, 215, 144, 52, 146, 238, 40, 45, 211, 165, 28, 98, 143, 72, 16, 68, 65, 105, 228, 150, 45, 194, 10, 90, 172, 171, 1, 224, 255, 176, 254, 202, 81, 23, 169, 123, 145, 169, 241, 113, 84, 144, 55, 108, 70, 254, 13, 122, 67, 2, 192, 25, 165, 236, 188, 221, 192, 179, 181, 191, 15, 109, 58, 211, 123, 190, 232, 223, 245, 250, 201, 131, 22, 216, 186}
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
