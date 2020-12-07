/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"math/rand"
	"reflect"
	"testing"
)

//checks that the derived keys are as is expected
func TestDerive_Consistency(t *testing.T) {
	expectedKeys := []string{
		"xnry59JCUEvvkzAr+S/IHUGHyY2NcWQynI5sYtWL0aE=",
		"cPTYRt8EIosS8MmpLZMfNEUIUPT7aqwWliscrBJQ6Vk=",
		"7UUQcBh0rzBGXH7TZoGCAu596kJWIzgncTqgjuKj89s=",
		"JPzdfI7shMZdrGEk/CgCxCkiiRSWu36UyVDrFI619wQ=",
	}
	// Generate keys, fingerprints and messages
	var keyIds []uint32
	var data [][]byte
	keyPrng := rand.New(rand.NewSource(42))
	dataPrng := rand.New(rand.NewSource(69))
	for i := 0; i < len(expectedKeys); i++ {
		keyIds = append(keyIds, keyPrng.Uint32())

		dataBytes := make([]byte, 64)
		dataPrng.Read(dataBytes)
		data = append(data, dataBytes)
	}

	h, _ := blake2b.New256(nil)

	//encrypt messages with fingerprints and check they match the expected
	for i := 0; i < len(data); i++ {
		h.Reset()
		key := derive(h, data[i], keyIds[i])

		//check that the key is 256 bits long
		if len(key) != 32 {
			t.Errorf("Key should be 256 bits, is %v instead", 64*len(key))
		}

		// Decode base64 encoded expected message
		expectedKey, _ := base64.StdEncoding.DecodeString(expectedKeys[i])

		if !reflect.DeepEqual(key, expectedKey) {
			t.Errorf("derive() did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", i, key, expectedKey)
			fmt.Println(base64.StdEncoding.EncodeToString(key))
		}
	}
}

//checks that the keynum has an impact on the output key
func TestDerive_KeyNum(t *testing.T) {
	const numTests = 25

	h, _ := blake2b.New256(nil)

	keyPrng := rand.New(rand.NewSource(42))
	dataPrng := rand.New(rand.NewSource(69))

	for i := 0; i < numTests; i++ {
		h.Reset()

		data := make([]byte, 64)
		dataPrng.Read(data)

		num1 := keyPrng.Uint32()
		num2 := keyPrng.Uint32()

		key1 := derive(h, data, num1)
		key2 := derive(h, data, num2)

		if bytes.Equal(key1, key2) {
			t.Errorf("Key set %v generated with the same data but "+
				"diferent keyNums are the same", i)
		}
	}
}

//checks that the data has an impact on the output key
func TestDerive_Data(t *testing.T) {
	const numTests = 25

	h, _ := blake2b.New256(nil)

	keyPrng := rand.New(rand.NewSource(42))
	dataPrng := rand.New(rand.NewSource(69))

	for i := 0; i < numTests; i++ {
		h.Reset()

		num := keyPrng.Uint32()

		data1 := make([]byte, 64)
		dataPrng.Read(data1)

		data2 := make([]byte, 64)
		dataPrng.Read(data2)

		key1 := derive(h, data1, num)
		key2 := derive(h, data2, num)

		if bytes.Equal(key1, key2) {
			t.Errorf("Key set %v generated with the same keyNum but "+
				"diferent data are the same", i)
		}
	}
}
