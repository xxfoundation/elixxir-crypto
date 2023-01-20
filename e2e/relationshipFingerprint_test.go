////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"gitlab.com/xx_network/crypto/cyclic"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"testing"
)

// show that every input changes the output hash
func TestMakeRelationshipFingerprint(t *testing.T) {
	grp := getGroup()

	// create a list to store the created fingerprints, it will be iterated
	// though to show none are the same
	var fpList [][]byte

	//create 9 fingerprints, all with different arrangements of inputs
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			for k := 0; k < 4; k++ {
				for l := 0; l < 4; l++ {
					pubKeyA := grp.NewIntFromUInt(uint64(2 + i))
					pubKeyB := grp.NewIntFromUInt(uint64(20 + j))
					sender := id.NewIdFromUInt(uint64(1+k), id.User, t)
					receiver := id.NewIdFromUInt(uint64(1+l), id.User, t)

					fpList = append(fpList, MakeRelationshipFingerprint(pubKeyA,
						pubKeyB, sender, receiver))
				}

			}
		}
	}

	//show that no fingerprints are the same
	for i := 0; i < len(fpList); i++ {
		for j := i + 1; j < len(fpList); j++ {
			if bytes.Equal(fpList[i], fpList[j]) {
				t.Errorf("fingerprint %d and %d are the same\n"+
					"\t first: %v \n\t second: %v", i, j, fpList[i], fpList[j])
			}
		}
	}
}

func getGroup() *cyclic.Group {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}
