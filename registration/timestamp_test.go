////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"bytes"
	"crypto/rand"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

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

var expectedSig = []byte{165, 7, 83, 28, 238, 213, 69, 91, 200, 248, 80, 95, 42, 242, 182, 72, 18, 112, 15, 48, 17, 152, 149, 111, 179, 234, 74, 48, 2, 175, 0, 19, 9, 77, 157, 179, 108, 153, 61, 117, 178, 27, 191, 172, 139, 62, 228, 149, 137, 24, 223, 224, 219, 1, 175, 152, 14, 139, 101, 133, 254, 101, 122, 170, 193, 203, 105, 9, 69, 40, 202, 173, 30, 125, 175, 116, 74, 189, 198, 118, 104, 202, 197, 186, 223, 153, 80, 93, 19, 110, 140, 30, 166, 130, 166, 179, 141, 67, 88, 87, 232, 251, 156, 90, 100, 217, 162, 116, 136, 192, 161, 45, 95, 67, 147, 81, 179, 62, 63, 241, 83, 227, 84, 158, 217, 12, 178, 248}

var expected_N = []byte{195, 159, 123, 88, 55, 24, 254, 233, 218, 210, 210, 219, 239, 13, 55, 110, 180, 8, 108, 226, 106, 3, 221, 96, 57, 41, 49, 82, 141, 228, 86, 230, 148, 97, 78, 92, 140, 224, 87, 244, 183, 161, 179, 239, 84, 229, 162, 140, 164, 236, 100, 12, 231, 246, 56, 176, 94, 67, 96, 183, 72, 20, 28, 97, 115, 128, 12, 87, 96, 37, 166, 226, 216, 134, 237, 9, 220, 99, 158, 140, 43, 123, 123, 41, 133, 142, 152, 249, 2, 181, 15, 15, 182, 0, 239, 128, 179, 134, 250, 11, 187, 6, 238, 112, 140, 64, 140, 110, 230, 243, 147, 198, 138, 223, 196, 55, 55, 196, 221, 128, 173, 98, 159, 98, 171, 120, 201, 157}

var expected_D = []byte{191, 83, 226, 45, 123, 102, 5, 27, 240, 27, 182, 131, 201, 32, 162, 16, 178, 32, 115, 110, 86, 198, 4, 228, 177, 195, 106, 44, 21, 255, 56, 71, 56, 228, 154, 225, 198, 31, 61, 167, 105, 90, 204, 67, 206, 66, 242, 98, 160, 131, 91, 175, 139, 199, 179, 214, 59, 187, 166, 130, 92, 10, 223, 93, 114, 142, 87, 208, 71, 94, 104, 102, 168, 208, 47, 200, 235, 56, 2, 75, 98, 234, 52, 66, 100, 60, 104, 213, 78, 99, 17, 109, 26, 169, 22, 118, 109, 138, 204, 69, 155, 92, 135, 46, 248, 114, 155, 134, 217, 33, 93, 161, 145, 189, 33, 211, 118, 154, 60, 112, 220, 13, 1, 206, 22, 105, 198, 65}

var expected_Dp = []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147, 183, 136, 1, 206, 242, 195, 61, 10, 45,
	254, 120, 69, 105, 57, 179, 128, 164, 116, 238, 187, 223, 176, 41, 247, 26, 235, 101, 50, 86, 38, 160, 109,
	145, 97, 219, 168, 204, 157, 22, 228, 7, 216, 82, 31, 67, 19, 141, 90, 126, 78, 200, 149, 185}

var expected_Dq = []byte{159, 52, 202, 32, 119, 12, 161, 248, 78, 228, 121, 208, 38, 188, 81, 167, 254, 148, 41, 127, 214, 107, 83, 27, 92, 128, 42, 243, 52, 88, 2, 203, 12, 47, 218, 162, 228, 7, 178, 122, 187, 223, 138, 82, 147, 183, 98, 42, 107, 143, 58, 2, 67, 103, 17, 218, 27, 62, 233, 177, 243, 22, 193, 137}

var expectedPrimes = [][]byte{
	[]byte{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85},
	[]byte{233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
}

// Smoke test
func TestSignVerify(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// use insecure seeded rng to reproduce key
	notRand := &CountingReader{count: uint8(10)}

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

	userPrivKey, err := rsa.GenerateKey(notRand, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	// Sign data
	userPubKeyPem := string(rsa.CreatePublicKeyPem(userPrivKey.GetPublic()))
	sig, err := SignWithTimestamp(notRand, serverPrivKey, testTime.UnixNano(), userPubKeyPem)
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

	// Test the verification
	err = VerifyWithTimestamp(serverPrivKey.GetPublic(), testTime.UnixNano(), userPubKeyPem, sig)
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

	userPrivKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	sig, err = SignWithTimestamp(notRand, serverPrivKey, testTime.UnixNano(), userPubKeyPem)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	// Test the verification
	err = VerifyWithTimestamp(serverPrivKey.GetPublic(), testTime.UnixNano(), userPubKeyPem, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}
}
