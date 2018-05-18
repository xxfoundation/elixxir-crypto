package verification

import (
	"gitlab.com/privategrity/crypto/hash"
)

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

	for i := 0; i < len(mic); i++ {
		if newmic[i] != mic[i] {
			return false
		}
	}

	return true
}