package e2e

import (
	b64 "encoding/base64"
	"errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

var grp *cyclic.Group

// Build global group for tests to utilise
func TestMain(m *testing.M) {
	// Create group
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	q := large.NewInt(2)
	grp = cyclic.NewGroup(p, g, q)

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
	expectedMsgs := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAABYgz2TELVPUF/A+j5OoH9dH9I7o3gbpTTgDLrV5G+C7" +
		"7Ovg32eaji3JYILRy2I5nA==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAABh3RDWZ+xopq9MEQXqXeahPXZLybtJiYZJ0bgCVS7vY" +
			"+gMnBcPz/ooYe53aqmegog==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAABBCVGaWzWyNfGgcmSvOK6IN3tU5QB4oP22MekAWLFlW" +
			"Jc8IBzZ9ZEZxjx6aXfPVbA==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAABG0Rl/iSaFTqWFdaGX5fJ7O7Fyq07E4v8MrCCCycpMD" +
			"IYVLYUUQ9jXDR1uWHHBDjg==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAC/GkLmfE8yyxi/5HnR3vhn4tVIPptDdIDtTlZfojS4Y" +
			"ytXnJ9vCSDQCgSkclb788A==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAACMOEjBhxcZBxBbW+FOjleNPmaTgMQe4PHZyf2MSFMVh" +
			"tZSe0UmptHi0xyjcTu34+A==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAACVzgCnEW7qRvAf4HrG4eNWs+vyzrQuq0Tgwaw0bikF3" +
			"KiC1bhuXoV4sh6jP7wauzg==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAsqB6hbTVSFU7ov+dKpxa9dbvlTyLTbyxC42oBU/qzm" +
			"nWw9dJ7sGxf6k9cHFCIipA==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAHUwuP2lpnRvb2ySDoQoLLegZACJ8bTSTSSZJuc1RzK" +
			"nRmNHw+20PGMIE16j/93fg==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAABfwh+g8TjarMCSwQ5/+iQ74ERacLPQYhSllnNaYEcC6" +
			"DktqYQFCn3Q6pmzTQ3ryZg==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAACMsHzvmvNnuduYoyWbKZ0gUKhQ8nAEfztI6zjV8IhBp" +
			"vcX785P8tVxNHw6N94BW4A==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAADSyooMO+lKLNdAeIECSH6OZQxbIyN3iHwtMzw44xXKD" +
			"l/hj2/G99c40GCLxgf+0xg==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAACkM0VG/dXT1hoDtB1CjZJDFx9WmPt80F772FLGguhf3" +
			"Hw2S1bKf40Bp0w9Yd1LulA==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAIQKCEiP1ZSsrlm3azWu48K5yLpZGjqOKm/xC2xkx7B" +
			"KLSCi0jeOIkXdsf4RfihFA==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAABozziWUxxnqgwoMKQHHxkS1gXEQZIFVKiMafIot+ojF" +
			"4Dfn4tDkATjG63mHdjI4Og==",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAwUE5Sy3VATxGqi54qlphxwvzjZx5a2WF62x2qdlhPm" +
			"acch5rvexEOKo9fsWhgxBg==",
	}
	// Generate keys and messages
	var keys []*cyclic.Int
	var msgs [][]byte
	keyPrng := rand.New(rand.NewSource(3271645196))
	rand.Seed(3102644637)
	msgBytes := make([]byte, 40)
	for i := 0; i < 16; i++ {
		keys = append(keys, grp.NewInt(keyPrng.Int63()))
		rand.Read(msgBytes)
		msgs = append(msgs, msgBytes)
	}

	for i := 0; i < len(msgs); i++ {
		encMsg := EncryptUnsafe(grp, keys[i], msgs[i])

		// Decode base64 encoded expected message
		expectedMsg, _ := b64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("EncryptUnsafe() did not produce the correct message\n\treceived: %#v\n\texpected: %#v", encMsg, expectedMsg)
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
