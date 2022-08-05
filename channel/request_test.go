package channel

import (
	"crypto/ed25519"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

// TestSignRequest_VerifyRequest generates a set of rsa and ed25519 keys and
// tests signing & verifying a Request using SignRequest and VerifyRequest
func TestSignRequest_VerifyRequest(t *testing.T) {
	rng := csprng.NewSystemRNG()
	rsaPriv, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("Failed to generate rsa private key: %+v", err)
	}

	edPub, _, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %+v", err)
	}

	ts := time.Now().UnixNano()

	sig, err := SignRequest(edPub, ts, rsaPriv, rng)
	if err != nil {
		t.Fatalf("Failed to sign request: %+v", err)
	}

	err = VerifyRequest(sig, edPub, ts, rsaPriv.GetPublic())
	if err != nil {
		t.Fatalf("Failed to verify request: %+v", err)
	}
}
