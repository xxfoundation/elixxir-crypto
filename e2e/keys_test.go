////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

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

//test consistency for DeriveReKey
func TestDeriveReKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"e/br4X5+UOH24+yINEKjhw/MEKzivNJJzvn3tPL2hVU=",
		"e4aMisC9bnY5JUT36hTiUQFjjrf3DF92kKKWmfZDInI=",
		"uufiizFsJwIa+/WDthUxCziSMZ9Afu24+8k2sOAz+2A=",
		"jRwJaIX04ILQv1mR9l8eVQvQGM2kjKeXoXQz5gcox3Q=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		k := DeriveReKey(dhkey, keyNum)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveReKey()")
}

//test consistency for DeriveKeyFingerprint
func TestDeriveKeyFingerprint_Consistency(t *testing.T) {
	expectedKeys := []string{
		"biUwFTuy+udrvH9iMCjBfen4seZAC9Q/5yZMwtVVTyk=",
		"Nv+cWM+lTzxEmtpk0h7Cr4O+GK7F5QTYSguywmnL4jw=",
		"pLLv4zWiydGW0ZU/8AxQYHZavBjm/Fw8KuE5dqgLPgo=",
		"15CDZZA2O1ck7PgyarTdT4wGcykQNfTsJJePy5OAJh8=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		fp := DeriveKeyFingerprint(dhkey, keyNum)
		return fp[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKeyFingerprint()")
}

//test consistency for DeriveReKeyFingerprint
func TestDeriveReKeyFingerprint_Consistency(t *testing.T) {
	expectedKeys := []string{
		"IaXR6e7UXWMXWDPzCrOBkpjfu0vxHbg0bYf0OZg4K9E=",
		"f5HYovwi5VBfuD1xgEMW9109FbgqKtpxIzRd9drOs/k=",
		"bDcv10RwH6oanu+XS8dTy5fPFXfN84yMNj9LiOcYN2c=",
		"/K/XG4NS1UUuDuxxPaf7cBRDmo11vHn3CGf8fYA6DEg=",
	}

	d := func(dhkey *cyclic.Int, keyNum uint32) []byte {
		fp := DeriveReKeyFingerprint(dhkey, keyNum)
		return fp[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveReKeyFingerprint()")
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
		rekey := DeriveReKey(basekey, keyNum)
		fp := DeriveKeyFingerprint(basekey, keyNum)
		refp := DeriveReKeyFingerprint(basekey, keyNum)

		list := make([][]byte, 4)
		list[0] = key[:]
		list[1] = rekey[:]
		list[2] = fp[:]
		list[3] = refp[:]

		names := []string{"key", "rekey", "fingerprint", "reKeyFingerprint"}

		for x := 0; x < 4; x++ {
			for y := x + 1; y < 4; y++ {
				if bytes.Equal(list[x], list[y]) {
					t.Errorf("on set %v %s and %s are equal: "+
						"%s: %v, %s: %s", i, names[x], names[y], names[x],
						list[x], names[y], list[y])
				}
			}
		}
	}
}
