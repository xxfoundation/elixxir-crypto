////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package verification

import (
	"bytes"
	"gitlab.com/elixxir/crypto/hash"
)

//TODO: Remove package? These 2 funcs aren't used anywhere in the project
func GenerateMIC(hashee [][]byte, length uint64) []byte {

	h, _ := hash.NewCMixHash()

	for i := 0; i < int(len(hashee)); i++ {
		h.Write(hashee[i])
	}

	var mic []byte

	for uint64(len(mic)) < length {
		mic = h.Sum(mic)
	}

	return mic[0:length]

}

func CheckMic(hasheeList [][]byte, mic []byte) bool {

	newmic := GenerateMIC(hasheeList, uint64(len(mic)))

	return bytes.Equal(mic, newmic)
}
