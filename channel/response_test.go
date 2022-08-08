package channel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
	"time"
)

// TestSignResponse_VerifyResponse generates two sets of ed25519 keys and
// tests signing & verifying a response using SignChannelLease and VerifyChannelLease
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

	sig := SignChannelLease(edPub1, lease, edPriv2)

	ok := VerifyChannelLease(sig, edPub1, lease, edPub2)
	if !ok {
		t.Fatal("Failed to verify signature")
	}
}

func TestSignVerify_Consistency(t *testing.T) {
	edPub1 := []byte{50, 35, 84, 147, 53, 22, 216, 211, 28, 7, 148, 12, 78, 87, 208, 187, 86, 76, 164, 86, 239, 23, 108, 113, 132, 145, 219, 3, 176, 219, 68, 187}

	edPub2 := []byte{123, 118, 86, 100, 82, 92, 47, 197, 45, 158, 10, 162, 28, 221, 135, 87, 113, 251, 44, 232, 59, 160, 119, 134, 104, 113, 104, 218, 101, 161, 12, 197}
	edPriv2 := []byte{232, 76, 88, 197, 38, 8, 204, 108, 64, 45, 54, 199, 10, 70, 31, 48, 45, 193, 136, 154, 233, 71, 219, 211, 16, 81, 147, 20, 149, 139, 62, 119, 123, 118, 86, 100, 82, 92, 47, 197, 45, 158, 10, 162, 28, 221, 135, 87, 113, 251, 44, 232, 59, 160, 119, 134, 104, 113, 104, 218, 101, 161, 12, 197}

	lease := uint64(1659978469802846000)

	expected := "J8eeoX2ffWbr81Ch2a9vmVbIvwowN/6tjOAIMZvHd/9NyIuuxSTaToXDggyCbD8Gma+2v6olg0BJ3m3Z3bluDw=="
	expectedBytes, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		t.Fatalf("Failed to decode expected sig: %+v", err)
	}
	sig := SignChannelLease(edPub1, lease, edPriv2)
	if !bytes.Equal(sig, expectedBytes) {
		t.Errorf("Did not get expected signature\n\tExpected: %+v\n\tReceived: %+v\n", expected, base64.StdEncoding.EncodeToString(sig))
	}

	ok := VerifyChannelLease(sig, edPub1, lease, edPub2)
	if !ok {
		t.Fatal("Failed to verify signature")
	}
}
