////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package contact

import (
	"encoding/base64"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

var expectedContact = []string{
	"<xxc(2)r79ksZZ/jFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QhytEufu5cbHgAAAAAAAAAAAAAAAAAAAAACADtQyzHOSDW8804N0pzSB+pVxxc>",
	"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAB7Ugdw/BAr6TEMemGbQnZN+AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AFVXQWcvWWROMXZBSzBIZlQ1R1NuaGp3PT070VC4Dw7K0pKK+/0NKg/ArQ==xxc>",
	"<xxc(2)D4S63Ezjb70AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjAFVMnA1dmd1WEhqaHNMcjY2SUc0S25VUkNLUXUwOGtEeXFRdz09LFVSbnZENEE9PSxVU1Z0WEVta3N0Z2ZhQUtFY0hBPT0726UuG590SuoxosnNslgHBw==xxc>",
	"<xxc(2)GwU/J15wKeEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6S8FK46CJiPJAAACADvKUBFgINED6kQtR2WpM3Psxxc>",
	"<xxc(2)/6g/AhbB1A4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6Qj/J+1va1fjsgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAO7m6OGypIENidTOM8dTAoqc=xxc>",
	"<xxc(2)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAOz09OSin/a/ZEfCXTcBTWMU=xxc>",
	"<xxc(2)ugKdkg6eo50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6SR7OWmxvLxKhAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAFVkVE9YWGlrcW9yZz07GlH9+RpHzzyudWw92EYGQg==xxc>",
	"<xxc(2)XMCYoCcs5+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6QfDMrfm2pchngEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeABVcWh3YkkrRWNTTzBYVTUxb1gzYnlwdz09LFVtTHhrM2c1ZDFwYmxMZmRnOXNOR1hpbWczS1Jxd3c9PTvz8PKXygJ5mhJFOUX0KQY3xxc>",
	"<xxc(2)jJtC2D9RBTEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6T2DKp+64UoZcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AFVvTlZ3RXp0OG1jSzRmVzN3M1Y3eWcyY1pCdz09O8dY3g71/hMqvc/qJ587MVs=xxc>",
	"<xxc(2)WnzDHpJX9IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIAB7Ugdw/BAr6WjQA9fwDEYOKAAAAAAAAAAAAAAAAAAAAAAAAAAAAGwAVWFYZz0sVTJhWE9ZdjZjR0E9PSxVUEJrenFSYlhPRHVaUEdsSm1VV3dzTS9qM0M3Qi9KWT07zmmJXN9xJq5gp21nEEkmqg==xxc>",
}


// Consistency test for unmarshal version "2".
func TestContact_unmarshalVer2_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(32))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}

// Consistency test for unmarshal version "1".
func TestContact_unmarshalVer1_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(32))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}

// Consistency test for unmarshal version "0".
func TestContact_unmarshalVer0_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var contacts []Contact

	// Generate test contacts
	for i := 0; i < 10; i++ {
		contacts = append(contacts, Contact{
			ID:             id.NewIdFromUInt(prng.Uint64(), id.User, t),
			DhPubKey:       getGroup().NewInt(prng.Int63()),
			OwnershipProof: make([]byte, prng.Int63n(255)),
			Facts:          fact.FactList{},
		})

		// Add facts to contact
		for j := 0; j < prng.Intn(5); j++ {
			username := make([]byte, prng.Intn(32))
			prng.Read(username)
			newFact, err := fact.NewFact(fact.Username, base64.StdEncoding.EncodeToString(username))
			if err != nil {
				t.Errorf("Failed to generate new fact (%d %d): %+v", i, j, err)
			}
			contacts[i].Facts = append(contacts[i].Facts, newFact)
		}

		// Set some fields to nil for certain contact
		switch i {
		case 1:
			contacts[i].ID = nil
		case 2:
			contacts[i].DhPubKey = nil
		case 3:
			contacts[i].OwnershipProof = nil
		case 4:
			contacts[i].Facts = nil
		case 5:
			contacts[i] = Contact{}
		}
	}

	for i, c := range contacts {
		expected, err := Unmarshal([]byte(expectedContact[i]))
		if err != nil {
			t.Errorf("Unmarshal() failed to unmarshal contact %d: %+v", i, err)
		}
		if !Equal(expected, c) {
			t.Errorf("Contacts %d do not match.\nexpected: %s\nreceived: %s",
				i, expected, c)
		}
	}
}
