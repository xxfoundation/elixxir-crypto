package channel

import (
	"crypto/ed25519"
	"golang.org/x/crypto/blake2b"
	"io"
	"strings"
)

type Language uint8
const (
	English Language = iota
)



type Identity struct{
	PubKey ed25519.PublicKey

	Honorific CodeNamePart
	Adjective CodeNamePart
	Noun      CodeNamePart

	Codename  string
	Color    string
	Extension string

	CodesetVersion uint8
}

func GenerateIdentity(rng io.Reader)(ed25519.PrivateKey, Identity, error){
	pub, priv, err := ed25519.GenerateKey(rng)
	if err!=nil{
		return nil, Identity{}, err
	}

	i := ConstructIdentity(pub)

	return priv, i, nil
}

func ConstructIdentity(pub ed25519.PublicKey)Identity{
	h, _ := blake2b.New256(nil)

	honorific := generateCodeNamePart(h, pub, honorificSalt, honorifics)
	adjective := generateCodeNamePart(h, pub, adjectiveSalt, adjectives)
	noun := generateCodeNamePart(h, pub, nounSalt, nouns)

	if honorific.Generated!=""{
		adjective.Generated = strings.Title(adjective.Generated)
	}

	if honorific.Generated!="" || adjective.Generated!=""{
		noun.Generated = strings.Title(noun.Generated)
	}

	i := Identity{
		PubKey:    pub,
		Honorific: honorific,
		Adjective: adjective,
		Noun:      noun,
		Codename:  honorific.Generated + adjective.Generated + noun.Generated,
		Color: generateColor(h,pub),
		Extension: generateExtension(h,pub),
	}
	return i
}