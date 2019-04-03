package cmix

import (
	"fmt"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"reflect"
	"testing"
)

// For creating PRNG salt
type systemPRNG struct{}

func (s *systemPRNG) Read(b []byte) (int, error) { return rand.Read(b) }
func (s *systemPRNG) SetSeed(seed []byte) error  { return nil }

func TestEncryptDecrypt(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	// Fill message with random payload and associated data
	payloadArr := make([]byte, rng.Intn(100))
	associatedDataArr := make([]byte, rng.Intn(100))
	rand.Read(payloadArr)
	rand.Read(associatedDataArr)
	msg := format.Message{
		Payload:        format.DeserializePayload(payloadArr),
		AssociatedData: format.DeserializeAssociatedData(associatedDataArr),
	}

	// Create random slice of base keys
	size := rng.Intn(100)
	baseKeys := make([]*cyclic.Int, size)
	for i := 0; i < size; i++ {
		baseKeys[i] = grp.NewInt(rng.Int63())
	}

	// Create salt
	salt := NewSalt(csprng.Source(&systemPRNG{}), 16)

	// Get encrypted message
	encMsg := EncryptDecrypt(grp, &msg, baseKeys, salt)

	// Get encryption key
	encKey := keyGen(grp, baseKeys, salt)

	// Invert and multiply the key with the message
	grp.Inverse(encKey, encKey)
	multPayload := grp.Mul(encKey, grp.NewIntFromBytes(encMsg.SerializePayload()), grp.NewInt(1))
	multAssociatedData := grp.Mul(encKey, grp.NewIntFromBytes(encMsg.SerializeAssociatedData()), grp.NewInt(1))

	testMsg := format.Message{
		Payload:        format.DeserializePayload(multPayload.Bytes()),
		AssociatedData: format.DeserializeAssociatedData(multAssociatedData.Bytes()),
	}

	if !reflect.DeepEqual(encMsg.SerializePayload(), testMsg.SerializePayload()) {
		t.Errorf("EncryptDecrypt() did not produce the correct payload\n\treceived: %d\n\texpected: %d", encMsg.SerializePayload(), testMsg.SerializePayload())
	}

	if !reflect.DeepEqual(encMsg.SerializeAssociatedData(), testMsg.SerializeAssociatedData()) {
		t.Errorf("EncryptDecrypt() did not produce the correct associated data\n\treceived: %d\n\texpected: %d", encMsg.SerializeAssociatedData(), testMsg.SerializeAssociatedData())
	}

	fmt.Printf("msg PL:     %d\n", msg.SerializePayload())
	fmt.Printf("test PL:    %d\n", encMsg.SerializePayload())
	fmt.Printf("encrypt PL: %d\n\n", testMsg.SerializePayload())
	fmt.Printf("msg AD:     %d\n", msg.SerializeAssociatedData())
	fmt.Printf("test AD:    %d\n", testMsg.SerializeAssociatedData())
	fmt.Printf("encrypt AD: %d\n", encMsg.SerializeAssociatedData())
}
