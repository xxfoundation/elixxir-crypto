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
	token := "acme-test-token"
	timestamp := uint64(5432345)
	sig, err := SignAcmeToken(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token")
	}

	err = VerifyAcmeToken(pk.GetPublic(), sig, token, timestamp)
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
	token := "acme-test-token"
	timestamp := uint64(5432345)

	expectedSig := []byte{18, 168, 91, 160, 155, 22, 175, 190, 40, 83, 71, 126, 11, 156, 235, 73, 97, 46, 61, 208, 202, 95, 55, 98, 112, 41, 114, 101, 93, 219, 98, 112, 81, 175, 135, 146, 231, 59, 169, 246, 128, 140, 84, 255, 241, 26, 208, 199, 187, 102, 32, 219, 70, 37, 118, 174, 215, 193, 158, 173, 228, 87, 116, 26, 208, 175, 40, 187, 48, 203, 235, 70, 33, 124, 74, 227, 69, 104, 48, 104, 36, 41, 202, 143, 191, 64, 222, 31, 88, 135, 209, 24, 119, 56, 126, 67, 57, 57, 230, 178, 219, 127, 241, 36, 203, 171, 2, 151, 224, 5, 126, 122, 87, 174, 67, 113, 253, 201, 194, 44, 193, 181, 2, 50, 61, 237, 194, 236}
	sig, err := SignAcmeToken(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token: %+v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignACMEToken\n\tExpected: %+v\n\tReceived: %+v", expectedSig, sig)
	}

	err = VerifyAcmeToken(pk.GetPublic(), sig, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}
