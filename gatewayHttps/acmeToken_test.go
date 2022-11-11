package gatewayHttps

import (
	"bytes"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
)

func TestSignVerify_AcmeToken(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	ip := "0.0.0.0:11420"
	token := "acme-test-token"
	timestamp := uint64(5432345)
	sig, err := SignAcmeToken(rng, pk, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token")
	}

	err = VerifyAcmeToken(pk.GetPublic(), sig, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}

func TestSignVerify_AcmeToken_Consistency(t *testing.T) {
	rng := &CountingReader{count: uint8(0)}
	pk, err := rsa.GenerateKey(rng, 1024)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	ip := "0.0.0.0:11420"
	token := "acme-test-token"
	timestamp := uint64(5432345)

	expectedSig := []byte{66, 114, 33, 238, 193, 210, 237, 10, 3, 51, 96, 208, 52, 3, 150, 20, 88, 163, 38, 106, 10, 16, 42, 29, 64, 190, 209, 43, 184, 46, 208, 162, 186, 81, 102, 205, 218, 180, 237, 29, 248, 211, 213, 87, 42, 218, 155, 244, 11, 73, 41, 143, 175, 77, 76, 181, 206, 172, 121, 5, 111, 249, 149, 245, 80, 227, 61, 187, 23, 93, 64, 88, 225, 40, 143, 188, 253, 65, 70, 18, 118, 59, 113, 91, 162, 112, 74, 249, 229, 231, 204, 234, 112, 3, 125, 171, 30, 177, 32, 121, 62, 203, 8, 239, 20, 110, 162, 146, 44, 51, 52, 155, 57, 36, 185, 106, 51, 165, 110, 219, 237, 49, 248, 3, 100, 129, 232, 22}
	sig, err := SignAcmeToken(rng, pk, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token: %+v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignACMEToken\n\tExpected: %+v\n\tReceived: %+v", expectedSig, sig)
	}

	err = VerifyAcmeToken(pk.GetPublic(), sig, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}
