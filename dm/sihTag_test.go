package dm

import (
	"crypto/ed25519"
	"math/rand"
	"testing"
)

func TestMakeSenderSihTag_Consistency(t *testing.T) {
	expected := []string{
		"o5zhSEohWggRFFyK2xGVG+TTFeOGaKzOiqJ9FsqUnvI=",
		"hhhGy8geMNAlWVxMS+PKQ07G+Nx9aoxY+TDZox6VYbw=",
		"lOQN8y4jgyz+beWIudg5P8Qm0JLXdovOw30Dca+bGto=",
		"gYMGjCWg0M33c5WBpMmhtl37NyQuVw5SU51eLtenZ20=",
		"LBPETMFjo3Snu/4DDcUM2tVCwVieUvCOl4L3bhC0Glw=",
	}

	rng := rand.New(rand.NewSource(980592))

	for _, exp := range expected {
		_, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, _, _ := ed25519.GenerateKey(rng)

		tag := MakeSenderSihTag(themPub, mePriv)
		if tag != exp {
			t.Errorf("Unexpected tag.\nexpected: %q\nreceived: %q", exp, tag)
		}
	}
}

func TestMakeReceiverSihTag_Consistency(t *testing.T) {
	expected := []string{
		"uOEdUQbiRLnJWuqWxTbVQOwKrNMVZmJOffYBdcYbGs4=",
		"eWlwtjd79mzLiLjKOP11RWrDU9rYf23xzdbKcRTimXI=",
		"ErkmZsLHKdEKlFP/BQhutsJCHT/0aQxmK+OF0LyA9Qg=",
		"9vhwk5EL1wQN5tA7RO1KXfVNSK9vezOHBjgVqzHLUgg=",
		"9l6flgusfpbUneRdnAOGGLC4t3H6EvY+itQvK/64fpk=",
	}

	rng := rand.New(rand.NewSource(439884))

	for _, exp := range expected {
		_, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, _, _ := ed25519.GenerateKey(rng)

		tag := MakeReceiverSihTag(themPub, mePriv)
		if tag != exp {
			t.Errorf("Unexpected tag.\nexpected: %q\nreceived: %q", exp, tag)
		}
	}
}

func TestMakeSihTag_Differences2(t *testing.T) {
	const numTests = 1000

	rng := rand.New(rand.NewSource(761489))

	for i := 0; i < numTests; i++ {
		mePub, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, themPriv, _ := ed25519.GenerateKey(rng)

		results := make([]string, 0, 4)

		tag := MakeReceiverSihTag(themPub, mePriv)
		results = append(results, tag)

		tag = MakeReceiverSihTag(mePub, themPriv)
		results = append(results, tag)

		tag = MakeSenderSihTag(mePub, themPriv)
		results = append(results, tag)

		tag = MakeSenderSihTag(themPub, mePriv)
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

func Test_makeSihTag_Consistency(t *testing.T) {
	expected := []string{
		"sSh1cCa+kulZi9q0F6jsBh5OrUF7YyG+p14hceD9LJM=",
		"9SOxGae69L7ThS4K07DqRachON86X1WoWDf4/zV7LDM=",
		"7VN4Czq6XFfSMM+hlYuFMgQHk/8gRS9Lgo1qHE2yXEg=",
		"x6YlgeWB/DA63NaYXxX0XaPeNoqqqVLWue1UuvnIaqM=",
		"S46dc09jKGsU1SpArge2NgDNYaN9FDZ+UohesF8DSiE=",
	}

	rng := rand.New(rand.NewSource(554987))

	for _, exp := range expected {
		mePub, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, _, _ := ed25519.GenerateKey(rng)

		tag := makeSihTag(themPub, mePriv, mePub)
		if tag != exp {
			t.Errorf("Unexpected tag.\nexpected: %q\nreceived: %q", exp, tag)
		}
	}
}

func Test_makeSihTag_Differences(t *testing.T) {
	const numTests = 1000

	rng := rand.New(rand.NewSource(511843))

	for i := 0; i < numTests; i++ {
		mePub, mePriv, _ := ed25519.GenerateKey(rng)
		themPub, themPriv, _ := ed25519.GenerateKey(rng)

		results := make([]string, 0, 4)

		// Every other one uses the same public key, and because the public/
		// private key pairs are interchangeable—due to the internal DH
		// operation—those will be the same. Outputs that are the same
		// mathematical parity will be the same, different parities will be
		// different.

		tag := makeSihTag(themPub, mePriv, mePub)
		results = append(results, tag)

		tag = makeSihTag(themPub, mePriv, themPub)
		results = append(results, tag)

		tag = makeSihTag(mePub, themPriv, mePub)
		results = append(results, tag)

		tag = makeSihTag(mePub, themPriv, themPub)
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
