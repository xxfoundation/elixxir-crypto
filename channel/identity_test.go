package channel

import (
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

func TestConstructIdentity(t *testing.T) {
	numtests := 100

	rng := &csprng.SystemRNG{}
	codenames := make([]string, 0, numtests)

	for i:=0;i<numtests;i++{
		id, _ := GenerateIdentity(rng)
		codenames = append(codenames, id.Codename + "#" + id.Extension +
			id.Color)
	}

	for i:=0;i<numtests;i++{
		for j:=i+1;j<numtests;j++{
			if codenames[i]==codenames[j]{
				t.Errorf("2 generated codenames are the same, %d vs %d",
					i, j)
			}
		}
	}
}
