////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package authorize

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Unit test
func TestSignVerify(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// use insecure seeded rng to reproduce key
	notRand := &CountingReader{count: uint8(0)}

	serverPrivKey, err := rsa.GenerateKey(notRand, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}
	serverPrivKey.Precompute()

	publicKey := serverPrivKey.Public().(*rsa.PublicKey)
	if bytes.Compare(publicKey.GetN().Bytes(), expected_N) != 0 {
		t.Fatalf("SignVerify error: "+
			"Bad N value in pre-canned private key."+
			"\n\tExpected %v\n\tReceived: %v", expected_N, publicKey.GetN().Bytes())
	}

	if !bytes.Equal(serverPrivKey.GetD().Bytes(), expected_D) ||
		!bytes.Equal(serverPrivKey.GetDp().Bytes(), expected_Dp) ||
		!bytes.Equal(serverPrivKey.GetDq().Bytes(), expected_Dq) {
		t.Fatalf("SignVerify error: "+
			"Bad D-value(s) in pre-canned private key."+
			"\n\tExpected D value %v\n\tReceived D value: %v"+
			"\n\tExpected Dp value: %v\n\tReceived Dp value: %v"+
			"\n\tExpected Dq value: %v\n\tReceived Dp value: %v",
			expected_D, serverPrivKey.GetD().Bytes(),
			expected_Dp, serverPrivKey.GetDp().Bytes(),
			expected_Dq, serverPrivKey.GetDq().Bytes())
	}

	ps := serverPrivKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if bytes.Compare(ps[i].Bytes(), expectedPrimes[i]) != 0 {
			t.Fatalf("SignVerify error: "+
				"Bad prime %d in pre-canned private key."+
				"\n\tExpected: %v\n\tReceived: %v", i, expectedPrimes[i], ps[i].Bytes())
		}
	}

	// Sign data
	sig, err := Sign(notRand, testTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	// Check that signature outputted is expected
	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("SignVerify error: "+
			"Signature was not expected with pre-canned value. Were crypto dependencies were updated?"+
			"\n\tExpected: %v\n\tReceived: %v", expectedSig, sig)
	}

	// Generate data required for verification
	delta := 24 * time.Hour * 2
	testNow := testTime.Add(delta / 2)

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	testId, err := xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Test the verification
	err = Verify(testNow, testTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}

	/*  -------- Test with random keys -------- */

	serverPrivKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	sig, err = Sign(notRand, testTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	testId, err = xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Test the verification
	err = Verify(testNow, testTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}

}

// Error path for verify
func TestVerify_Error(t *testing.T) {
	// Set up test
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	// Generate a pre-canned time for consistent testing
	signedTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// use insecure seeded rng to reproduce key
	notRand := &CountingReader{count: uint8(0)}

	sig, err := Sign(notRand, signedTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	testId, err := xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Check when signed timestamp is out of bounds (below the lower bound)
	delta := 24 * time.Hour * 2
	testNow := signedTime.Add(delta * 3)
	// Test the verification
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: "+
			"Signed time %s should be beyond lower bound given delta %s and test now being %s", signedTime, delta, testNow)
	}

	// Check when signed timestamp is out of bounds (above the upper bound)
	testNow = signedTime.Add(-delta * 3)
	// Test the verification
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: "+
			"Expected error: Signed time %s should be beyond upper bound given delta %s and test now being %s", signedTime, delta, testNow)
	}

	// Reinitialize timestamps
	testNow = signedTime.Add(delta / 2)

	// Trigger failed ID check
	badSalt := make([]byte, 32)
	copy(badSalt, "error")

	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		badSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: " +
			"Expected error: IDs should not match with different data passed in")
	}

	// Trigger failed signature check
	badSig := []byte("signature")
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, badSig)
	if err == nil {
		t.Fatalf("SignVerify error: " +
			"Expected error: Signature check should have failed with bad signature passed in")
	}

}

var expectedSig = []byte{27, 99, 175, 180, 242, 103, 112, 24, 170, 152, 167, 185, 41, 80, 64, 95, 87,
	195, 153, 34, 123, 88, 71, 247, 30, 108, 7, 227, 84, 78, 12, 168, 253, 223, 26, 103, 165, 243, 163,
	149, 197, 59, 168, 156, 255, 246, 22, 53, 1, 116, 250, 202, 50, 229, 61, 127, 88, 158, 27, 155, 13, 35,
	24, 137, 166, 46, 43, 208, 241, 229, 42, 125, 76, 103, 208, 232, 146, 97, 54, 108, 22, 218, 136, 78, 143,
	227, 54, 83, 51, 207, 195, 242, 150, 189, 78, 232, 78, 45, 211, 194, 32, 104, 87, 105, 143, 255, 44, 212,
	234, 75, 44, 195, 169, 187, 168, 204, 248, 72, 69, 251, 244, 106, 246, 16, 52, 95, 101, 26}

var expected_N = []byte{191, 1, 94, 54, 139, 93, 174, 126, 207, 161, 246, 207, 44, 14, 119, 103, 224, 227,
	112, 137, 46, 97, 34, 115, 84, 199, 205, 102, 148, 87, 177, 163, 45, 81, 15, 105, 95, 244, 38, 249, 108,
	129, 56, 147, 147, 56, 132, 120, 20, 90, 74, 231, 48, 38, 204, 33, 38, 222, 72, 102, 56, 192, 255, 247,
	123, 132, 17, 227, 249, 80, 233, 194, 219, 49, 197, 149, 160, 230, 101, 28, 10, 46, 136, 21, 214, 201,
	238, 66, 198, 120, 87, 98, 152, 249, 131, 53, 14, 13, 49, 121, 229, 115, 33, 240, 222, 235, 20, 89, 186,
	52, 200, 116, 55, 15, 254, 0, 21, 60, 116, 189, 20, 121, 236, 106, 244, 136, 36, 201}

var expected_D = []byte{46, 169, 28, 228, 226, 66, 238, 127, 216, 37, 78, 239, 233, 105, 87, 78, 47, 40, 32,
	179, 194, 122, 196, 57, 188, 122, 90, 249, 54, 63, 254, 11, 72, 228, 198, 137, 13, 129, 205, 139, 157, 48,
	44, 44, 17, 8, 251, 131, 130, 37, 84, 171, 9, 158, 80, 187, 192, 141, 8, 206, 192, 10, 149, 252, 233, 60,
	250, 138, 143, 216, 250, 92, 162, 154, 217, 200, 8, 105, 127, 179, 168, 43, 211, 6, 104, 200, 186, 167, 49,
	39, 29, 124, 232, 45, 226, 110, 116, 195, 240, 98, 189, 208, 46, 64, 170, 57, 130, 239, 32, 230, 213, 85, 8,
	191, 12, 89, 72, 169, 14, 226, 199, 139, 195, 216, 108, 78, 18, 33}

var expected_Dp = []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147, 183, 136, 1, 206, 242, 195, 61, 10, 45,
	254, 120, 69, 105, 57, 179, 128, 164, 116, 238, 187, 223, 176, 41, 247, 26, 235, 101, 50, 86, 38, 160, 109,
	145, 97, 219, 168, 204, 157, 22, 228, 7, 216, 82, 31, 67, 19, 141, 90, 126, 78, 200, 149, 185}

var expected_Dq = []byte{108, 163, 66, 203, 107, 33, 193, 73, 233, 160, 63, 200, 104, 30, 190, 70, 230, 157, 60,
	197, 101, 27, 187, 67, 227, 154, 57, 194, 98, 24, 184, 64, 224, 151, 54, 191, 95, 21, 181, 61, 221, 148, 51,
	188, 92, 18, 178, 58, 218, 145, 48, 185, 89, 15, 175, 55, 215, 142, 45, 182, 86, 12, 172, 53}

var expectedPrimes = [][]byte{
	[]byte{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
		47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
		73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85},
	[]byte{228, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
		141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
		162, 165},
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
