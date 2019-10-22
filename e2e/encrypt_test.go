package e2e

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

var grp *cyclic.Group

// Build global group for tests to utilise
func TestMain(m *testing.M) {
	// Create group
	primeString := "E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B" +
		"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE" +
		"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F" +
		"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041" +
		"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45" +
		"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209" +
		"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29" +
		"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E" +
		"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2" +
		"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696" +
		"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E" +
		"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873" +
		"847AEF49F66E43873"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	grp = cyclic.NewGroup(p, g)

	os.Exit(m.Run())
}

// Tests the functionality of Encrypt() and Decrypt() by encrypting a message
// and check that it is the same when decrypting
func TestEncryptDecrypt(t *testing.T) {
	// Create key and message
	key := grp.NewInt(2)
	msg := []byte{5, 12, 11}

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Checks that leading zeroes in a message are not stripped
func TestEncryptDecrypt_LeadingZeroes(t *testing.T) {

	// Create key and message
	key := grp.NewInt(3)
	msg := []byte{0, 0, 11, 5, 255, 0}

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Ensures that encrypted messages are consistency encrypted to the same value
// (when replacing the random number generater with a pseudo one)
func TestEncrypt_Consistency(t *testing.T) {
	// Set up expected values with base64 encoding
	expectedMsgs := []string{"Qg5IeGohcWaCM8cvXinWjfOa5h8z2r/t9escYdF0thDWkXh" +
		"KlBcUroVBSV5fMXiTKgQ7GyquSu6cDEtD3XocscCr3sIewXkk+B2mPuJaOch7Gxm9MPh" +
		"ZibCIyhKYZQCw4eYHEruLP/n+3muDVbjT2K7jV9MkRJkU37JTfm9XiBGEwZOiAx8r4f1" +
		"kAX34ISgQoOlWfiIMYkxNDg9leOz8jo4JzFY2dKWYrdnqPWboTlYAm0dwH+dKo0zj69a" +
		"hU0zZ1I9q2uVc65LyCqnCAUk0MwUYIuoYvNHm+yw5SjZWms2nK3mFgMevOYonJRkO2h2" +
		"wusjlQoNv/5b+c/QfWWvfPiMTSwLakiwFqrtkIWqpDvePu2j7zYcngGMMLj1LhaJ6Vgy" +
		"E/b357UxScPZWdBsFETq5wfX6AVGE8a785yrSLEQTtRBLDV+kaDHepzeirWL30txOSbi" +
		"jNI6ZqdGud99g3pxNWVEvJe3rigBsx+rDSxCBCIkWeeyIbWH9VyNc159p0JuVXUQv6ix" +
		"nlWQ04iCQ",
		"MCEGyIYyNR0cE6W34+PRvJowhEWLw7n/eO0VDJYchG4syfzEidfE4QRcWydxiPxrNp5W" +
			"3qmcoqLUKRgIse46+Ci3hi0gCDI2nf8sqqyCmhA78gJ2JBbor9tbdZiyoDQyxo+yNB6f" +
			"OegtBXfjobc6fHmtRPyujBqyWOI7yZ+GbSfb9OwnFUP957D53FoK0AAxW5Rm1c4F7n8x" +
			"WZ8SRQYxGTs2ZwZ+AyJcL340aklz3aB8TCNb69S8XiEktrEL0PGp83dkTXISyNABurLx" +
			"GD9Axgyy3RxQFQwD7aKw8YNnf0GdZ30wXg8FCItz21WcvY6B7CslzJCd4xAZ+dBG9CHC" +
			"6FcYXs9EHcm4jEVxXNUrY/93U1VaN3cisktcH2BIfzR6JEvgGhUpXyuKC0rQZTbjq/kd" +
			"+5tanEnqc1PxDC0/eU2R4FQ4nQevQmwIY+b7UTL3jwvA5DvqXyFwJqU/u+4I9Q1UzttB" +
			"d2o2jd8yfKnbrHYWRHi4VPoW7aKyQMx/b/K8hmGj2BRHMlGt3xjm6hlT",
		"gB+zC+aZY/xL27WLwxMc6n+mmTRfih0Q7LCTeAbgIYUmJaLO5xLiVb6Pu4HXekz2i7Bl" +
			"4N2BqOAgbm+0XJW773G/W3wfvXa2DVI57a47MOId0CcHhzcWGyOFDevQLiePwC/LXTE+" +
			"R2X9FeCxG7a2RHEygziuMRgo6xXGLSJH/HCpbNTKpoVR+fbbBTDlOpKUc1jDQWFILnMm" +
			"gq38mI2RaJTaumYvjUTZNCFRexTEh6omwdPBlrLmShm6ShFaOrcLRhQt2Ae9DZOG8x8A" +
			"YaoSspIwlHABnDY76Oyd3gyVZFNW3BmDjg+nP/PuzzvLCFv43dXn0YvCHHMb7DDjdYOY" +
			"SS/q3bsinJNvpeNNLWEiXJptNTtwUe4RXBB80a2Omj8mMTFikqyfI6bROlud8kIC+Jot" +
			"P7gUA/OqK7q0ygnLDfguWD8YVn/WXUz2i6dNj4Kqq6zvjJfhVTfc/s98aKQNyXRWu4Cb" +
			"icFB+k8hq7A69xlVvyAJBVEEWHAGTFRJlw9nIyunzRrwRzNHzw41ix6z",
		"TPYY8KiJH22Pr25bB9m/DEgBFs5CKLlMtgbEubki10F1tFKIF17MJ48yjBgU72vyzTl+" +
			"9LM3Ic1S87r6sHTda66zSQ/jzAn93na1SFLiVqZSE/kzZMrErqHhjjKTw4XFxHDZbTL4" +
			"avMbJEkNHRxm2+6O8alFNA2ypGGO6F3S9FwwSzTrBkP85cVJTsQ4Uie5PCDAXgGuc+ru" +
			"lRwvmaw9rXnpk/Oqtcgn3ojK245gI7AAN6vFxxxlnq3QoLkBl9Vq7IT7Elec8EIWrE/G" +
			"7d3SCCMUFlRQ3rCVgxJ72ZLAqjsEjQPLMrxKplgDg20PurhjmOJ4olMx4tJ4DYHYoJTW" +
			"5ouMKfdbkoblGgz8UrRu7ZMDaorSPU6Uq0MlzJ9V3iBJSEf6Z98m0Jn4UQMxdrpHplkc" +
			"lb0jlGmcGPW2zqbiqgbmqezmqXj5lqFSOEjThX0JZ0iSDps9EwZZoIRExCMT/jdenILm" +
			"Ve/wm8Wyr2f39bwlj7cHiN3cChc4nJz+UBEp05t2J2YVUrUqxdGkzKKQ",
	}
	// Generate keys and messages
	var keys []*cyclic.Int
	var msgs [][]byte
	keyPrng := rand.New(rand.NewSource(42))
	msgPrng := rand.New(rand.NewSource(69))
	for i := 0; i < len(expectedMsgs); i++ {
		msgBytes := make([]byte, format.ContentsLen)
		keys = append(keys, grp.NewInt(keyPrng.Int63()))
		msgPrng.Read(msgBytes[:format.ContentsLen-2])
		msgs = append(msgs, msgBytes)
	}

	for i := 0; i < len(msgs); i++ {
		encMsg := EncryptUnsafe(grp, keys[i], msgs[i])

		// Decode base64 encoded expected message
		expectedMsg, _ := b64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("EncryptUnsafe() did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", i, encMsg, expectedMsg)
			fmt.Println(b64.StdEncoding.EncodeToString(encMsg))
		}
	}
}

// Checks that Encrypt() correctly responds to errors
func TestEncrypt_ErrorOnLongMessage(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 4000)
	rand.Read(msgBytes)
	msg := msgBytes
	key := grp.NewInt(65)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Encrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("message too long"))
	}

	if encMsg != nil {
		t.Errorf("Encrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", encMsg, nil)
	}
}

// Checks that Decrypt() correctly responds to errors
func TestDecrypt_ErrorOnPaddingPrefix(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 40)
	rand.Read(msgBytes)
	msg := msgBytes
	key := grp.NewInt(65)

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Decrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("padding prefix invalid"))
	}

	if dncMsg != nil {
		t.Errorf("Decrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", dncMsg, nil)
	}
}
