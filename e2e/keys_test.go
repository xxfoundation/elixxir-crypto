////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"math/rand"
	"reflect"
	"gitlab.com/xx_network/primitives/id"
	"testing"
)

//test consistency for DeriveKey
func TestDeriveKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"/vvFJWjt4LhlpOAq3fZn4lfdmMh9X4ZHyMjCFz0UwRo=",
		"bdItjv5VMy4Xm40PH1iaBfLwx0Ni/9zIvbAJ/laUOSM=",
		"UzMNfY9ZkGieKr25hoH5zV+9+bsYKpHmh7Wl5qy38Qs=",
		"Aap7CrsET1cGf7YRdSe5xyL9ONuW3182a7VEiNZgjUA=",
	}

	d := func(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) []byte {
		k, _ := DeriveKey(dhkey, userID, keyNum)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKey()")
}

//test consistency for DeriveReKey
func TestDeriveReKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"UOkk/aCiZCa6MGPce43a57Htsf1UCMB6PnWtb32J+4s=",
		"4Mt2PhielEiF7r6zCKAZfhntEiclwiwmBRlaq0WaDRs=",
		"Lvg6VBla3+xOJFm5Qr6utGdQOq0R4bPopyud1jx9yVs=",
		"eqDT+PdbAIvQxWa+mBy5mE0/hK2Wb0WuIA8wvDw7jyA=",
	}

	d := func(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) []byte {
		k, _ := DeriveReKey(dhkey, userID, keyNum)
		return k[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveReKey()")
}

//test consistency for DeriveKeyFingerprint
func TestDeriveKeyFingerprint_Consistency(t *testing.T) {
	expectedKeys := []string{
		"32BOjB9FJ+gEUQYjDuyNHC5jxZYtmin8LuN6mfKOODE=",
		"yKsnV4xAauNhqi5YCiESeBSKksLQY5iH3+dWGmnwSig=",
		"ZOrWfR3KJGO2MsPAEAUe7Y0yWRtU9Mlpw8zlefmQrfY=",
		"a8LoB1Z5BNETBmD+tM7appp+oSXh4QbT6ePeAKrvS1Q=",
	}

	d := func(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) []byte {
		fp, _ := DeriveKeyFingerprint(dhkey, userID, keyNum)
		return fp[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveKeyFingerprint()")
}

//test consistency for DeriveReKeyFingerprint
func TestDeriveReKeyFingerprint_Consistency(t *testing.T) {
	expectedKeys := []string{
		"0p1yuGGuQPkGpMnZpQfkKSbulV+U63u1LHEp+MIEJp0=",
		"Elf7zHAPojPPOTBJcz0X9DJrjOtHsRe6cr1P9iqMAz8=",
		"yaJBcqK5vV4Iptom1QYgEEc/buIHcwojhQJrtZOO3Tg=",
		"Iu4UNlR5cwt778LN2WoUQEWUDjhqndlM/kflSCKZlTI=",
	}

	d := func(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) []byte {
		fp, _ := DeriveReKeyFingerprint(dhkey, userID, keyNum)
		return fp[:]
	}

	deriveConsistencyTester(t, expectedKeys, d, "DeriveReKeyFingerprint()")
}

func deriveConsistencyTester(t *testing.T, expectedKeys []string, d func(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) []byte, name string) {
	basekeyPrng := rand.New(rand.NewSource(42))
	userIDPrng := rand.New(rand.NewSource(69))
	keynumsPrng := rand.New(rand.NewSource(420))

	baseKeyLen := grp.GetP().ByteLen()

	for i := 0; i < len(expectedKeys); i++ {
		baseKeyBytes := make([]byte, baseKeyLen)
		basekeyPrng.Read(baseKeyBytes)
		baseKeyBytes[0] &= 0x7f
		basekey := grp.NewIntFromBytes(baseKeyBytes)

		userIDBytes := make([]byte, 33)
		userIDPrng.Read(userIDBytes)
		userID := id.ID{}
		copy(userID[:], userIDBytes)

		keyNum := keynumsPrng.Uint32()

		key := d(basekey, &userID, keyNum)

		if len(key[:]) != 32 {
			t.Errorf("Key should be 256 bits, is %v instead", 64*len(key))
		}

		expectedKey, _ := base64.StdEncoding.DecodeString(expectedKeys[i])

		if !reflect.DeepEqual(key[:], expectedKey) {
			t.Errorf("%s did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", name, i, key, expectedKey)
			//fmt.Println(base64.StdEncoding.EncodeToString(key[:]))
		}

	}
}

//verifies that all derived fingerprints and keys are different
func TestAllDifferent(t *testing.T) {
	const numtests = 25

	basekeyPrng := rand.New(rand.NewSource(42))
	userIDPrng := rand.New(rand.NewSource(69))
	keynumsPrng := rand.New(rand.NewSource(420))

	baseKeyLen := grp.GetP().ByteLen()

	for i := 0; i < numtests; i++ {
		baseKeyBytes := make([]byte, baseKeyLen)
		basekeyPrng.Read(baseKeyBytes)
		baseKeyBytes[0] &= 0x7f
		basekey := grp.NewIntFromBytes(baseKeyBytes)

		userIDBytes := make([]byte, 33)
		userIDPrng.Read(userIDBytes)
		userID := id.ID{}
		copy(userID[:], userIDBytes)

		keyNum := keynumsPrng.Uint32()

		key, _ := DeriveKey(basekey, &userID, keyNum)
		rekey, _ := DeriveReKey(basekey, &userID, keyNum)
		fp, _ := DeriveKeyFingerprint(basekey, &userID, keyNum)
		refp, _ := DeriveReKeyFingerprint(basekey, &userID, keyNum)

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
