////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

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

// Consistency test for Sign
func TestSignVerify_Consistency(t *testing.T) {
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

	publicKey := serverPrivKey.GetPublic()
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

}

// Consistency test for digest
func TestDigest_Consistency(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// Construct the hash
	options := rsa.NewDefaultOptions()

	receivedDigest := digest(options.Hash.New(), testTime)

	if !bytes.Equal(receivedDigest, expectedDigest) {
		t.Fatalf("Digest consistency error: "+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expectedDigest, receivedDigest)
	}
}

// Unit test
func TestSignVerify(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// Generate data required for verification
	delta := 24 * time.Hour * 2
	testNow := testTime.Add(delta / 2)

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	sig, err := Sign(rand.Reader, testTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

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

var expectedSig = []byte{9, 21, 121, 251, 79, 80, 177, 178, 105, 49, 106, 45, 233, 39, 146, 138, 196, 187, 79, 33, 157, 226, 172, 213, 67, 19, 58, 245, 69, 159, 71, 38, 69, 19, 222, 111, 146, 41, 220, 106, 81, 185, 70, 107, 112, 252, 52, 22, 247, 233, 26, 154, 62, 192, 95, 76, 62, 81, 106, 194, 251, 193, 199, 168, 235, 23, 31, 58, 99, 51, 111, 71, 204, 236, 172, 141, 89, 27, 158, 103, 58, 196, 90, 187, 251, 23, 10, 136, 244, 5, 148, 45, 47, 122, 205, 187, 189, 128, 9, 67, 125, 226, 197, 184, 197, 72, 232, 253, 133, 190, 178, 178, 208, 172, 167, 242, 129, 239, 175, 127, 149, 54, 133, 107, 190, 92, 78, 100}

var expected_N = []byte{195, 159, 123, 88, 55, 24, 254, 233, 218, 210, 210, 219, 239, 13, 55, 110, 180, 8, 108, 226, 106, 3, 221, 96, 57, 41, 49, 82, 141, 228, 86, 230, 148, 97, 78, 92, 140, 224, 87, 244, 183, 161, 179, 239, 84, 229, 162, 140, 164, 236, 100, 12, 231, 246, 56, 176, 94, 67, 96, 183, 72, 20, 28, 97, 115, 128, 12, 87, 96, 37, 166, 226, 216, 134, 237, 9, 220, 99, 158, 140, 43, 123, 123, 41, 133, 142, 152, 249, 2, 181, 15, 15, 182, 0, 239, 128, 179, 134, 250, 11, 187, 6, 238, 112, 140, 64, 140, 110, 230, 243, 147, 198, 138, 223, 196, 55, 55, 196, 221, 128, 173, 98, 159, 98, 171, 120, 201, 157}

var expected_D = []byte{191, 83, 226, 45, 123, 102, 5, 27, 240, 27, 182, 131, 201, 32, 162, 16, 178, 32, 115, 110, 86, 198, 4, 228, 177, 195, 106, 44, 21, 255, 56, 71, 56, 228, 154, 225, 198, 31, 61, 167, 105, 90, 204, 67, 206, 66, 242, 98, 160, 131, 91, 175, 139, 199, 179, 214, 59, 187, 166, 130, 92, 10, 223, 93, 114, 142, 87, 208, 71, 94, 104, 102, 168, 208, 47, 200, 235, 56, 2, 75, 98, 234, 52, 66, 100, 60, 104, 213, 78, 99, 17, 109, 26, 169, 22, 118, 109, 138, 204, 69, 155, 92, 135, 46, 248, 114, 155, 134, 217, 33, 93, 161, 145, 189, 33, 211, 118, 154, 60, 112, 220, 13, 1, 206, 22, 105, 198, 65}

var expected_Dp = []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147, 183, 136, 1, 206, 242, 195, 61, 10, 45, 254, 120, 69, 105, 57, 179, 128, 164, 116, 238, 187, 223, 176, 41, 247, 26, 235, 101, 50, 86, 38, 160, 109, 145, 97, 219, 168, 204, 157, 22, 228, 7, 216, 82, 31, 67, 19, 141, 90, 126, 78, 200, 149, 185}

var expected_Dq = []byte{159, 52, 202, 32, 119, 12, 161, 248, 78, 228, 121, 208, 38, 188, 81, 167, 254, 148, 41, 127, 214, 107, 83, 27, 92, 128, 42, 243, 52, 88, 2, 203, 12, 47, 218, 162, 228, 7, 178, 122, 187, 223, 138, 82, 147, 183, 98, 42, 107, 143, 58, 2, 67, 103, 17, 218, 27, 62, 233, 177, 243, 22, 193, 137}

var expectedPrimes = [][]byte{
	[]byte{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85},
	[]byte{233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
}

var expectedDigest = []byte{19, 149, 39, 88, 8, 30, 138, 147, 218, 69, 4, 210, 20, 204, 60, 29, 36, 6, 79, 131,
	171, 5, 188, 226, 27, 140, 45, 253, 67, 138, 229, 216}

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
