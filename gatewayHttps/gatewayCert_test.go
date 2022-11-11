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

	expectedSig := []byte{163, 150, 216, 198, 8, 105, 144, 120, 114, 244, 236, 195, 113, 170, 87, 20, 24, 102, 189, 47, 232, 160, 44, 40, 248, 115, 31, 171, 207, 188, 184, 203, 35, 206, 39, 151, 90, 75, 124, 9, 112, 255, 157, 133, 91, 160, 130, 31, 39, 15, 54, 65, 233, 213, 73, 232, 254, 216, 164, 60, 46, 4, 106, 86, 211, 250, 71, 10, 29, 233, 168, 146, 124, 228, 152, 5, 71, 78, 249, 145, 43, 240, 239, 146, 192, 254, 47, 243, 154, 190, 128, 124, 76, 188, 189, 77, 168, 82, 60, 146, 175, 59, 37, 176, 146, 69, 189, 204, 104, 111, 109, 209, 105, 176, 50, 153, 113, 139, 55, 31, 227, 6, 56, 26, 187, 174, 118, 68}
	sig, err := SignGatewayCert(rng, pk, cert)
	if err != nil {
		t.Fatalf("Failed to sign gateway certificate")
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("Failed to verify consistency for SignGatewayCert")
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
