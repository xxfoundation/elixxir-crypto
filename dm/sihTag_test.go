package dm

import (
	"crypto/ed25519"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

func TestMakeSihTag_Consistency(t *testing.T) {
	expecteds := []string{
		"7dblkU0g84UxNEn3iWP6MnzVBWF0yilScRm3OtLjymY=",
		"1Kct4dhzw7UP3/5V423TTyaKMMO8h6ZdFIkAEhZnY8g=",
		"39rZmPauxgqnt2rGvmL+P7Nk2KyxW8W5sqM9c7VYL9w=",
		"ku7SPT6gHC1mU2LY+gJ+9hFdsPycNBNQFmz3GAoGjMY=",
		"HzPD5DakK7hmnnsrfAPkAHGHEFIq70g2EGrxuPXjykk=",
	}

	rng := rand.New(rand.NewSource(123456))

	for _, expected := range expecteds {
		_, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, _, _ := ed25519.GenerateKey(rng)

		meID, _ := id.NewRandomID(rng, id.User)

		tag := MakeSihTag(themPub, mePriv, meID)
		if tag != expected {
			t.Errorf("Tag does not equal expected "+
				"\nexpected: '%s'\ntag: '%s'", expected, tag)
		}
	}
}

func TestMakeSihTag_Differences(t *testing.T) {
	const numTests = 1000

	rng := rand.New(rand.NewSource(123456))

	for i := 0; i < numTests; i++ {
		mePub, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, themPriv, _ := ed25519.GenerateKey(rng)

		meID, _ := id.NewRandomID(rng, id.User)
		themID, _ := id.NewRandomID(rng, id.User)

		results := make([]string, 0, 4)

		// every other one uses the same id, and because the pub/priv key
		// pairs are interchangeable due to the internal dh operation, those
		// will be the same. outputs that are the same mathematical parity
		// will be the same, different parity's will be different.

		tag := MakeSihTag(themPub, mePriv, meID)
		results = append(results, tag)

		tag = MakeSihTag(themPub, mePriv, themID)
		results = append(results, tag)

		tag = MakeSihTag(mePub, themPriv, meID)
		results = append(results, tag)

		tag = MakeSihTag(mePub, themPriv, themID)
		results = append(results, tag)

		for x := 0; x < 4; x++ {
			for y := x + 1; y < 4; y++ {
				if x%2 == y%2 {
					if results[x] != results[y] {
						t.Errorf("on test %d result %d (%s) not the same "+
							"as %d (%s)", i, x, results[x], y, results[y])
					}
				} else {
					if results[x] == results[y] {
						t.Errorf("on test %d result %d (%s) is the same "+
							"as %d (%s)", i, x, results[x], y, results[y])
					}
				}
			}
		}
	}
}
