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
		"ShPEi7JwZIzpIOPpUG9jBF3BRRozA+Z2JLDOXiT0YLc=",
		"YZ8M4uOyDxVAXTHk+pr4kdhTme8urtHPTnbBqAatlgw=",
		"IoTeCHeLlJ+MW9uuSOYoOVw6+TRQqmilRcChBP+4Tow=",
		"QeAllQ/0OVce0Wrg5m1GuW4x5cJRbE12wKW+xYJpM0U=",
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
