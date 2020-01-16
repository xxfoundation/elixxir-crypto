////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"testing"
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

// TestRSASmoke signs and verifies a datapacket, and reads all the values to
// ensure they match output that was previously computed.
func TestRSASmoke(t *testing.T) {
	expected_hash := []byte{14, 87, 81, 192, 38, 229, 67, 178, 232, 171,
		46, 176, 96, 153, 218, 161, 209, 229, 223, 71, 119, 143, 119,
		135, 250, 171, 69, 205, 241, 47, 227, 168}
	expected_D := []byte{46, 169, 28, 228, 226, 66, 238, 127, 216, 37, 78,
		239, 233, 105, 87, 78, 47, 40, 32, 179, 194, 122, 196, 57, 188,
		122, 90, 249, 54, 63, 254, 11, 72, 228, 198, 137, 13, 129, 205,
		139, 157, 48, 44, 44, 17, 8, 251, 131, 130, 37, 84, 171, 9, 158,
		80, 187, 192, 141, 8, 206, 192, 10, 149, 252, 233, 60, 250, 138,
		143, 216, 250, 92, 162, 154, 217, 200, 8, 105, 127, 179, 168,
		43, 211, 6, 104, 200, 186, 167, 49, 39, 29, 124, 232, 45, 226,
		110, 116, 195, 240, 98, 189, 208, 46, 64, 170, 57, 130, 239, 32,
		230, 213, 85, 8, 191, 12, 89, 72, 169, 14, 226, 199, 139, 195,
		216, 108, 78, 18, 33}
	expected_Dp := []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147,
		183, 136, 1, 206, 242, 195, 61, 10, 45, 254, 120, 69, 105, 57,
		179, 128, 164, 116, 238, 187, 223, 176, 41, 247, 26, 235, 101,
		50, 86, 38, 160, 109, 145, 97, 219, 168, 204, 157, 22, 228, 7,
		216, 82, 31, 67, 19, 141, 90, 126, 78, 200, 149, 185}
	expected_Dq := []byte{108, 163, 66, 203, 107, 33, 193, 73, 233, 160, 63,
		200, 104, 30, 190, 70, 230, 157, 60, 197, 101, 27, 187, 67, 227,
		154, 57, 194, 98, 24, 184, 64, 224, 151, 54, 191, 95, 21, 181,
		61, 221, 148, 51, 188, 92, 18, 178, 58, 218, 145, 48, 185, 89,
		15, 175, 55, 215, 142, 45, 182, 86, 12, 172, 53}

	expected_primes := [2][]byte{
		[]byte{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
			36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
			50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
			64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
			78, 79, 80, 81, 82, 83, 84, 85},
		[]byte{228, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
			111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
			122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
			133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
			144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
			155, 156, 157, 158, 159, 160, 161, 162, 165},
	}
	expected_sig := []byte{44, 53, 102, 124, 185, 100, 135, 6, 92, 85, 224,
		191, 137, 121, 204, 48, 50, 128, 253, 169, 170, 220, 166, 50,
		241, 81, 166, 207, 226, 165, 52, 211, 210, 116, 24, 158, 210,
		209, 82, 252, 24, 219, 129, 247, 238, 24, 230, 162, 202, 138,
		94, 245, 108, 13, 125, 217, 213, 164, 183, 76, 36, 223, 123,
		66, 22, 194, 69, 52, 147, 10, 248, 163, 24, 183, 204, 47, 250,
		117, 81, 182, 148, 38, 140, 129, 204, 25, 37, 226, 225, 43, 10,
		114, 94, 129, 29, 218, 179, 245, 11, 132, 245, 77, 73, 110, 237,
		242, 225, 81, 118, 16, 240, 197, 251, 16, 121, 8, 67, 211, 20,
		127, 68, 124, 21, 32, 60, 80, 69, 49}
	expected_N := []byte{191, 1, 94, 54, 139, 93, 174, 126, 207, 161, 246,
		207, 44, 14, 119, 103, 224, 227, 112, 137, 46, 97, 34, 115, 84,
		199, 205, 102, 148, 87, 177, 163, 45, 81, 15, 105, 95, 244, 38,
		249, 108, 129, 56, 147, 147, 56, 132, 120, 20, 90, 74, 231, 48,
		38, 204, 33, 38, 222, 72, 102, 56, 192, 255, 247, 123, 132, 17,
		227, 249, 80, 233, 194, 219, 49, 197, 149, 160, 230, 101, 28,
		10, 46, 136, 21, 214, 201, 238, 66, 198, 120, 87, 98, 152, 249,
		131, 53, 14, 13, 49, 121, 229, 115, 33, 240, 222, 235, 20, 89,
		186, 52, 200, 116, 55, 15, 254, 0, 21, 60, 116, 189, 20, 121,
		236, 106, 244, 136, 36, 201}

	data := []byte("Hello, World")
	opts := NewDefaultOptions()
	hash := opts.Hash.New()
	// NOTE: The Sum() interface appends to data, and doesn't
	// produce a clean hash, that's why we remove it from the beginning!
	hashed := hash.Sum(data)[len(data):]

	if bytes.Compare(hashed, expected_hash) != 0 {
		t.Logf("\nData: %v\nHash: %v\n", data, hashed)
		t.Errorf("Unexpected hash value, expected: %v", expected_hash)
	}

	notRand := &CountingReader{count: uint8(0)}

	privateKey, err := GenerateKey(notRand, 1024)
	privateKey.Precompute() // Generates Dq/Dp

	if err != nil {
		t.Errorf("%v", err)
	}
	publicKey := privateKey.Public().(*PublicKey)
	if bytes.Compare(publicKey.GetN().Bytes(), expected_N) != 0 {
		t.Logf("N: %v", publicKey.GetN().Bytes())
		t.Errorf("Bad N-val, expected: %v", expected_N)
	}

	if bytes.Compare(privateKey.GetD().Bytes(), expected_D) != 0 ||
		bytes.Compare(privateKey.GetDp().Bytes(), expected_Dp) != 0 ||
		bytes.Compare(privateKey.GetDq().Bytes(), expected_Dq) != 0 {
		t.Logf("\nPrivateKey D-Vals: \n\t%v \n\t%v \n\t%v",
			privateKey.GetD().Bytes(),
			privateKey.GetDp().Bytes(),
			privateKey.GetDq().Bytes(),
		)
		t.Errorf("Bad D-Values!")
	}

	ps := privateKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if bytes.Compare(ps[i].Bytes(), expected_primes[i]) != 0 {
			t.Logf("Prime %d: %v", i, ps[i].Bytes())
			t.Errorf("Bad prime value for prime %d", i)
		}
	}

	signature, err := Sign(notRand, privateKey, opts.Hash, hashed, nil)
	if err != nil {
		t.Errorf("%v", err)
	}

	if bytes.Compare(signature, expected_sig) != 0 {
		t.Logf("\nSignature: %v", signature)
		t.Errorf("Bad Signature, expected: %v", expected_sig)
	}

	verification := Verify(publicKey, opts.Hash, hashed, signature, nil)

	if verification != nil {
		t.Errorf("Could not verify signature: %v", verification)
	}
}
