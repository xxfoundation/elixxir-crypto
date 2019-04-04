package cmix

import (
	"fmt"
	"gitlab.com/elixxir/crypto/csprng"
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

	// Create salt
	salt := NewSalt(csprng.Source(&systemPRNG{}), 16)

	// Get encrypted message
	size := 10
	baseKeys := makeBaseKeys(size)

	encMsg := ClientEncryptDecrypt(grp, &msg, salt, baseKeys)

	// Get encryption key
	keyEncInv := ClientKeyGen(grp, salt, baseKeys)

	multPayload := grp.NewInt(1)
	multAssociatedData := grp.NewInt(1)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(msg.SerializePayload()), multPayload)
	grp.Mul(keyEncInv, grp.NewIntFromBytes(msg.SerializeAssociatedData()), multAssociatedData)

	fmt.Printf("multPayload 2: %s\n", multPayload.Text(10))

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
}
