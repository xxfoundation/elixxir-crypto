package e2e

import (
	b64 "encoding/base64"
	"errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

var grp cyclic.Group

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
	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp = cyclic.NewGroup(p, seed, g, rng)

	os.Exit(m.Run())
}

func TestEncryptDecrypt(t *testing.T) {

	// Create key and message
	key := cyclic.NewInt(3)
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

func TestEncryptDecrypt_LeadingZeroes(t *testing.T) {

	// Create key and message
	key := cyclic.NewInt(3)
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

func TestEncrypt_Consistency(t *testing.T) {
	// Set up expected values with base64 encoding
	expectedMsgs := []string{
		"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"}

	// Generate keys and messages
	var keys []*cyclic.Int
	var msgs [][]byte
	keyPrng := rand.New(rand.NewSource(3271645196))
	rand.Seed(3102644637)
	msgBytes := make([]byte, 40)
	for i := 0; i < 16; i++ {
		keys = append(keys, cyclic.NewInt(keyPrng.Int63()))
		rand.Read(msgBytes)
		msgs = append(msgs, msgBytes)
	}

	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(msgs); i++ {
		encMsg, err := encrypt(grp, keys[i], msgs[i], prng)

		if err != nil {
			t.Errorf("encrypt() produced an unexpected error\n\treceived: %#v\n\texpected: %#v", err, nil)
		}

		// Decode base64 encoded expected message
		expectedMsg, _ := b64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("encrypt() did not produce the correct message\n\treceived: %#v\n\texpected: %#v", encMsg, expectedMsg)
		}
	}
}

func TestEncrypt_ErrorOnLongMessage(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 4000)
	rand.Read(msgBytes)
	msg := msgBytes
	key := cyclic.NewInt(65)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Encrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("message too long"))
	}

	if encMsg != nil {
		t.Errorf("Encrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", encMsg, nil)
	}
}

func TestDecrypt_ErrorOnPaddingPrefix(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 40)
	rand.Read(msgBytes)
	msg := msgBytes
	key := cyclic.NewInt(65)

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Decrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("padding prefix invalid"))
	}

	if dncMsg != nil {
		t.Errorf("Decrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", dncMsg, nil)
	}
}
