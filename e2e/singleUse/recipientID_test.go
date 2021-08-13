package singleUse

import (
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/crypto/diffieHellman"
	"git.xx.network/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Tests that the generated IDs do not change.
func TestNewRecipientID_Consistency(t *testing.T) {
	expectedRIDs := []string{
		"8weTLQUZT0NXuJL6bt9BbksEt0LLywnvvHbMIO7Is0YD",
		"olmvbVz3Jgu/lh60yicuTWg15neBB2i/zcd9JZVz9/8D",
		"JWJAWiCARp+uLYg70YYCYB/1bsTH7Gr3M4mi2ACYhxMD",
		"onYyGcAjVcwr5rwqQweVxYYnYpgWWjGhiNA/CxnxmsYD",
		"nIQ/WrgPyl07IPStrcCHTe1+rWrEAxQiFtwzA+K1IMED",
		"tF+cgN69Xk7fAhHSzuD2diYmMpaaCsWCr1A7+Th1WUkD",
		"7UW7O94ZB94RJM5Ku4n6/BVREOO4+m7dQgqzzmpo0xgD",
		"ePDyChmF5Gxr/Ny/9AWgGlPMdqymJ3ivv7bg0dMDH64D",
		"f7RPMI/NHERKj6MW+bbl0bupBgnIvnOj5Xhum/ItTn8D",
		"MqXY49FVJoxeuRdQAwYfswf9Li3ZnCZ9fig+EbTl7BkD",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedRID := range expectedRIDs {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		unencryptedPayload := make([]byte, prng.Intn(500))
		prng.Read(unencryptedPayload)

		testRID := NewRecipientID(pubKey, unencryptedPayload)

		if expectedRID != testRID.String() {
			t.Errorf("NewRecipientID() did not return the expected ID (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedRID, testRID)
		}

		if testRID.GetType() != id.User {
			t.Errorf("NewRecipientID() did not return expected ID type (%d)."+
				"\nexpected: %s\nreceived: %s", i, id.User, testRID.GetType())
		}
	}
}

// Tests that all generated IDs are unique.
func TestNewRecipientID_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	IDs := make(map[*id.ID]struct {
		pubKey           *cyclic.Int
		encryptedPayload []byte
	})

	// Test with same public key but differing payloads
	for i := 0; i < testRuns; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength+i, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		for j := 0; j < testRuns; j++ {
			unencryptedPayload := make([]byte, prng.Intn(500)+j)
			prng.Read(unencryptedPayload)

			testID := NewRecipientID(pubKey, unencryptedPayload)

			if _, exists := IDs[testID]; exists {
				t.Errorf("Generated ID collides with previously generated ID (%d, %d)."+
					"\ncurrent ID:   key: %s  unencryptedPayload: %+v"+
					"\npreviouse ID: key: %s  unencryptedPayload: %+v"+
					"\nID:           %s", i, j,
					pubKey.Text(10), unencryptedPayload, IDs[testID].pubKey.Text(10),
					IDs[testID].encryptedPayload, testID)
			} else {
				IDs[testID] = struct {
					pubKey           *cyclic.Int
					encryptedPayload []byte
				}{pubKey, unencryptedPayload}
			}
		}
	}

	// Test with same payload but differing public key
	for i := 0; i < testRuns; i++ {
		unencryptedPayload := make([]byte, prng.Intn(500)+i)
		prng.Read(unencryptedPayload)
		for j := 0; j < testRuns; j++ {
			privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength+j, getGrp(), prng)
			pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())

			testID := NewRecipientID(pubKey, unencryptedPayload)

			if _, exists := IDs[testID]; exists {
				t.Errorf("Generated ID collides with previously generated ID (%d, %d)."+
					"\ncurrent ID:   key: %s  unencryptedPayload: %+v"+
					"\npreviouse ID: key: %s  unencryptedPayload: %+v"+
					"\nID:           %s", i, j,
					pubKey.Text(10), unencryptedPayload, IDs[testID].pubKey.Text(10),
					IDs[testID].encryptedPayload, testID)
			} else {
				IDs[testID] = struct {
					pubKey           *cyclic.Int
					encryptedPayload []byte
				}{pubKey, unencryptedPayload}
			}
		}
	}
}
