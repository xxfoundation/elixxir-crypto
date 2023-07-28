package codename

import (
	"gitlab.com/elixxir/crypto/hash"
	"strings"
)

func GenerateChannelCodename(input []byte) string {
	h := hash.CMixHash.New()
	adjective := generateCodeNamePart(h, input, adjectiveSalt, adjectives)
	noun := generateCodeNamePart(h, input, nounSalt, nouns)

	if adjective.Generated != "" {
		noun.Generated = strings.Title(noun.Generated)
	}
	return adjective.Generated + noun.Generated
}
