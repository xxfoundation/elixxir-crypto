///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"testing"
)

//test consistency for DeriveKey
func TestDeriveKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"2gQs27wW7ckb6zGUBibdyYs6/aBqJxK2YFW6hToO2EI=",
		"xJcc6R7CO8DYHMO1EPaoQosa6gGm+XUUT/h4zd3cAgA=",
		"2GcWd46Z/QFyjVGecwoWY7AMTsXU9WhLsqEJPAuPH8c=",
		"HfotB69pGLoD9prB4VYSayvWgxuKrXWAjEh8Upsx7c0=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		k := DeriveKey(dhkey, keyNum)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKey()")
}

func TestDeriveKey_Consistency_salt(t *testing.T) {

	salt := []byte("salt")

	//notice these are different from the test above
	expectedKeys := []string{
		"PI10XqqBtrUFjQb9KEO4berrvNi6X/Pnx3rfsf71D2E=",
		"uOKI3LAap9o7cFPevMVq5b8WYp7E7OCR9i31DsAFMBQ=",
		"hHxcaW2t3MDUxRCt25f9IKZ0mHVJCsz/sv12mhj4Et8=",
		"X12LBBqzOr6XdmkSB3CpcjtldeJFVE0quQSHOTwr9R8=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		k := DeriveKey(dhkey, keyNum, salt)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKey()")
}

func TestDeriveKey_Consistency_doubleSalt(t *testing.T) {

	salt := []byte("salt")
	salt2 := []byte("electricBoogaloo")

	//notice these are different from the test above and the one above that
	expectedKeys := []string{
		"VJONuzoQnwvjdNWZCwcA1n+r7lssoLG9sAUC0OLMIIk=",
		"9HzDPYpetfKK7YYgudLEDDRJiZFvqLxRqS/8gIWlndM=",
		"5DkJha9tw6c3uYmIX+0GAEAfNwMKoQspc1Fiqk2hLsY=",
		"ukk5qfWTi+5dldxkPgnN1zkb98V5Aspf3BttHeouqvM=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		k := DeriveKey(dhkey, keyNum, salt, salt2)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKey()")
}

//test consistency for DeriveKeyFingerprint
func TestDeriveKeyFingerprint_Consistency(t *testing.T) {
	expectedKeys := []string{
		"biUwFTuy+udrvH9iMCjBfen4seZAC9Q/5yZMwtVVTyk=",
		"Nv+cWM+lTzxEmtpk0h7Cr4O+GK7F5QTYSguywmnL4jw=",
		"JLLv4zWiydGW0ZU/8AxQYHZavBjm/Fw8KuE5dqgLPgo=",
		"V5CDZZA2O1ck7PgyarTdT4wGcykQNfTsJJePy5OAJh8=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		fp := DeriveKeyFingerprint(dhkey, keyNum)
		return fp[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKeyFingerprint()")
}

func deriveConsistencyTester(t *testing.T, expectedKeys []string, d func(dhkey *cyclic.Int, keyNum uint32) []byte, name string) {
	basekeyPrng := rand.New(rand.NewSource(42))
	keynumsPrng := rand.New(rand.NewSource(69))

	baseKeyLen := grp.GetP().ByteLen()

	for i := 0; i < len(expectedKeys); i++ {
		baseKeyBytes := make([]byte, baseKeyLen)
		basekeyPrng.Read(baseKeyBytes)
		baseKeyBytes[0] &= 0x7f
		basekey := grp.NewIntFromBytes(baseKeyBytes)

		userIDBytes := make([]byte, 33)
		userID := id.ID{}
		copy(userID[:], userIDBytes)

		keyNum := keynumsPrng.Uint32()

		key := d(basekey, keyNum)

		if len(key[:]) != 32 {
			t.Errorf("Key should be 256 bits, is %v instead", 64*len(key))
		}

		expectedKey, _ := base64.StdEncoding.DecodeString(expectedKeys[i])

		if !reflect.DeepEqual(key[:], expectedKey) {
			t.Errorf("%s did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", name, i, key, expectedKey)
			fmt.Println(base64.StdEncoding.EncodeToString(key[:]))
		}
	}
}

//verifies that all derived fingerprints and keys are different
func TestAllDifferent(t *testing.T) {
	const numtests = 25

	basekeyPrng := rand.New(rand.NewSource(42))
	keynumsPrng := rand.New(rand.NewSource(69))

	baseKeyLen := grp.GetP().ByteLen()

	for i := 0; i < numtests; i++ {
		baseKeyBytes := make([]byte, baseKeyLen)
		basekeyPrng.Read(baseKeyBytes)
		baseKeyBytes[0] &= 0x7f
		basekey := grp.NewIntFromBytes(baseKeyBytes)

		userIDBytes := make([]byte, 33)
		userID := id.ID{}
		copy(userID[:], userIDBytes)

		keyNum := keynumsPrng.Uint32()

		key := DeriveKey(basekey, keyNum)
		fp := DeriveKeyFingerprint(basekey, keyNum)

		list := make([][]byte, 2)
		list[0] = key[:]
		list[1] = fp[:]

		names := []string{"key", "fingerprint"}

		for x := 0; x < 2; x++ {
			for y := x + 1; y < 2; y++ {
				if bytes.Equal(list[x], list[y]) {
					t.Errorf("on set %v %s and %s are equal: "+
						"%s: %v, %s: %s", i, names[x], names[y], names[x],
						list[x], names[y], list[y])
				}
			}
		}
	}
}
