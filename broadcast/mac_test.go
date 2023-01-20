////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"encoding/base64"
	"math/rand"
	"testing"
)

// Tests consistency of makeMAC.
func Test_makeMAC_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedIDs := []string{
		"YM/+IErzGJmcBg6TPyEw9o6KtH5YzX6xF+f54ishrlg=",
		"Iiac3lN/HeV1B9wtB7u5Xs2oR2zuHte5AJ60TPwCK8U=",
		"UDnUiuBmTVtOyYBq9qWDmj69JPRbciDctqqLVy1+fJw=",
		"QKGQSaIF4OSlXY1dewitDGSdX5OHLW4B+YhKvZj9B5Q=",
		"U4J0dBJMNU93vwEE2k6Cy93VjIfXxpbpj7J/bBrWuOI=",
		"FJ+lWqLOVcdyMcD5uHvw+jJC1N87vtPaGxjb9b01HUs=",
		"I/RvJKBIeBgdKHjo2T35PWFPRz3pgm/IcD4ax8y5gxI=",
		"VkksyxgB2c7RKUjFnDax7W8Nn7B8y/0P4HwG5X6jxOg=",
		"Z9Q4ghbo6v+8Lzj1fuJv5kxvOERRVomQPGVlx2ZZszc=",
		"YSEOBOsCXF9HwqyOmAgCO7VY7vZY3z6xGRYDlTC1BtE=",
	}

	for i, expected := range expectedIDs {
		key := make([]byte, 16)
		prng.Read(key)
		payload := make([]byte, 64)
		prng.Read(payload)

		mac := makeMAC(key, payload)
		macStr := base64.StdEncoding.EncodeToString(mac)

		if expected != macStr {
			t.Errorf("MAC does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, macStr)
		}
	}
}

// Tests that changing single and multiple inputs to makeMAC always results in a
// unique MAC.
func Test_makeMAC_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const n = 10
	keys, payloads := make([][]byte, n), make([][]byte, n)

	for i := range keys {
		keys[i] = make([]byte, 16)
		prng.Read(keys[i])
		payloads[i] = make([]byte, 64)
		prng.Read(payloads[i])
	}

	macs := make(map[string]bool, n*n)

	for i, key := range keys {
		for j, payload := range payloads {
			mac := makeMAC(key, payload)
			macStr := base64.StdEncoding.EncodeToString(mac)

			if macs[macStr] {
				t.Errorf("MAC already exists in map (%d, %d)."+
					"\nMAC: %s\nkey: %v\npayload: %v\n",
					i, j, macStr, key, payload)
			} else {
				macs[macStr] = true
			}
		}
	}
}

// Tests that the generated MACs are verified by verifyMAC.
func Test_verifyMAC_GoodMACs(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		key := make([]byte, 16)
		prng.Read(key)
		payload := make([]byte, 64)
		prng.Read(payload)

		mac := makeMAC(key, payload)

		if !verifyMAC(key, payload, mac) {
			t.Errorf("MAC could not be verified (%d)."+
				"\nMAC:     %v\nkey:     %v\npayload: %v", i, mac, key, payload)
		}
	}
}

// Tests that the bad MACs are not verified by verifyMAC.
func Test_verifyMAC_BadMACs(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const numTests = 100

	for i := 0; i < numTests; i++ {
		key := make([]byte, 16)
		prng.Read(key)
		payload := make([]byte, 64)
		prng.Read(payload)

		mac := make([]byte, 32)
		prng.Read(mac)

		if verifyMAC(key, payload, mac) {
			t.Errorf("Bad MAC verified (%d)."+
				"\nMAC:     %v\nkey:     %v\npayload: %v", i, mac, key, payload)
		}
	}
}
