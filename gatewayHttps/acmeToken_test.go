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

	expectedSig := []byte{72, 2, 68, 89, 71, 60, 120, 197, 208, 190, 197, 133, 222, 11, 125, 193, 14, 172, 170, 74, 128, 169, 56, 134, 40, 157, 53, 227, 246, 141, 225, 163, 45, 34, 100, 170, 139, 165, 37, 81, 191, 217, 132, 238, 173, 255, 7, 156, 207, 92, 162, 189, 251, 46, 179, 170, 126, 252, 45, 107, 165, 75, 72, 77, 84, 54, 125, 207, 108, 221, 85, 147, 217, 249, 223, 235, 129, 202, 208, 210, 69, 65, 18, 43, 143, 109, 163, 209, 205, 228, 172, 193, 55, 227, 217, 129, 159, 221, 120, 165, 188, 190, 15, 185, 55, 34, 155, 124, 13, 26, 128, 225, 25, 219, 66, 77, 157, 76, 128, 209, 39, 0, 80, 190, 36, 176, 193, 79}
	sig, err := SignAcmeToken(rng, pk, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token: %+v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignACMEToken")
	}

	err = VerifyAcmeToken(pk.GetPublic(), sig, ip, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}
