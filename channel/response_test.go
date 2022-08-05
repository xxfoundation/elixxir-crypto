package channel

import (
	"crypto/ed25519"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
	"time"
)

// TestSignResponse_VerifyResponse generates two sets of ed25519 keys and
// tests signing & verifying a response using SignResponse and VerifyResponse
func TestSignResponse_VerifyResponse(t *testing.T) {
	rng := csprng.NewSystemRNG()

	edPub1, _, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %+v", err)
	}

	edPub2, edPriv2, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %+v", err)
	}

	lease := uint64(time.Now().UnixNano())

	sig := SignResponse(edPub1, lease, edPriv2)

	ok := VerifyResponse(sig, edPub1, lease, edPub2)
	if !ok {
		t.Fatal("Failed to verify signature")
	}
}
