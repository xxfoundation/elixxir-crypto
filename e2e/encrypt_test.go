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
	msg := cyclic.NewInt(4)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if dncMsg == msg {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

func TestEncrypt_Consistency(t *testing.T) {
	// Set up expected values with base64 encoding
	expectedMsgs := []string{
		"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",
	}

	// Generate keys and messages
	var keys, msgs []*cyclic.Int
	keyPrng := rand.New(rand.NewSource(3271645196))
	msgPrng := rand.New(rand.NewSource(3102644637))
	for i := 0; i < 16; i++ {
		keys = append(keys, cyclic.NewInt(keyPrng.Int63()))
		msgs = append(msgs, cyclic.NewInt(msgPrng.Int63()))
	}

	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(msgs); i++ {
		encMsg, err := encrypt(grp, keys[i], msgs[i], prng)

		if err != nil {
			t.Errorf("encrypt() produced an unexpected error\n\treceived: %#v\n\texpected: %#v", err, nil)
		}

		// Decode base64 encoded expected message
		expectedMsg, _ := b64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(expectedMsg, encMsg.Bytes()) {
			t.Errorf("encrypt() did not produce the correct message\n\treceived: %#v\n\texpected: %#v", expectedMsg, encMsg.Bytes())
		}
	}
}

func TestEncrypt_ErrorOnLongMessage(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 4000)
	rand.Read(msgBytes)
	msg := cyclic.NewIntFromBytes(msgBytes)
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
	grp := cyclic.NewGroup(p, seed, g, rng)

	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 40)
	rand.Read(msgBytes)
	msg := cyclic.NewIntFromBytes(msgBytes)
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
