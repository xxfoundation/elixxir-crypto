package codename

import (
	"gitlab.com/elixxir/crypto/hash"
	"strings"
)

func GenerateChannelCodename(input []byte) string {
	h := hash.CMixHash.New()
	honorific := generateCodeNamePart(h, input, honorificSalt, honorifics)
	adjective := generateCodeNamePart(h, input, adjectiveSalt, adjectives)
	noun := generateCodeNamePart(h, input, nounSalt, nouns)
	if honorific.Generated != "" {
		adjective.Generated = strings.Title(adjective.Generated)
	}

	if honorific.Generated != "" || adjective.Generated != "" {
		noun.Generated = strings.Title(noun.Generated)
	}
	return honorific.Generated + adjective.Generated + noun.Generated
}
