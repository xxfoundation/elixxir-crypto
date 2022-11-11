package gatewayHttps

import (
	"bytes"
	"fmt"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"strconv"
	"strings"
	"testing"
)

func TestSignVerify_GatewayCert(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	cert := []byte("I'm a tls certificate!")
	sig, err := SignGatewayCert(rng, pk, cert)
	if err != nil {
		t.Fatalf("Failed to sign gateway cert")
	}

	err = VerifyGatewayCert(pk.GetPublic(), sig, cert)
	if err != nil {
		t.Fatalf("Failed to verify signature on gateway cert: %+v", err)
	}
}

func TestSignVerify_GatewayCert_Consistency(t *testing.T) {
	rng := &CountingReader{count: uint8(0)}
	pk, err := rsa.GenerateKey(rng, 1024)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	cert := []byte("I'm a tls certificate!")

	expectedSig := []byte{81, 8, 5, 19, 98, 247, 61, 192, 86, 168, 72, 74, 192, 5, 84, 216, 229, 31, 4, 32, 183, 189, 44, 161, 63, 47, 50, 93, 206, 155, 181, 23, 228, 29, 180, 242, 253, 144, 142, 145, 72, 84, 90, 233, 225, 226, 93, 105, 75, 137, 217, 209, 73, 71, 217, 49, 12, 174, 136, 63, 200, 54, 177, 12, 187, 62, 25, 86, 234, 169, 117, 3, 0, 94, 123, 158, 175, 210, 240, 60, 57, 87, 45, 81, 158, 232, 29, 173, 179, 209, 228, 224, 15, 232, 79, 22, 22, 10, 193, 21, 168, 4, 30, 199, 29, 54, 241, 20, 22, 93, 163, 153, 174, 244, 91, 120, 63, 72, 39, 107, 121, 199, 56, 166, 187, 71, 155, 37}
	sig, err := SignGatewayCert(rng, pk, cert)
	if err != nil {
		t.Fatalf("Failed to sign gateway certificate")
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignGatewayCert\n\tExpected: %+v\n\tReceived: %+v", expectedSig, sig)
	}

	err = VerifyGatewayCert(pk.GetPublic(), sig, cert)
	if err != nil {
		t.Fatalf("Failed to verify signature on gateway cert: %+v", err)
	}
}

type CountingReader struct {
	count uint8
}

// Read just counts until 254 then starts over again
func (c *CountingReader) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		c.count = (c.count + 1) % 255
		b[i] = c.count
	}
	return len(b), nil
}

func parseData(b []byte) {
	var membersArr []string
	for _, m := range b {
		membersArr = append(membersArr, strconv.Itoa(int(m)))
	}

	members := strings.Join(membersArr, ", ")

	fmt.Printf("%v\n", members)

}
