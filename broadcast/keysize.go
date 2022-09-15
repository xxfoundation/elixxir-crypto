package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"math"
)

const (
	minKeysize = 1024/8
)

// calculateKeySize finds the optimal key size and number of subpackets smaller
// than the keysize and larger than the minkeysize.
// both paylaodSize and maxKeysize should be in bytes
func calculateKeySize(payloadSize, maxKeysize int)(selectedKeySize int, selectedN int){

	sizedPayloadSize := MaxSizedBroadcastPayloadSize(payloadSize)

	//get the bounds
	lower := int(math.Ceil(float64(sizedPayloadSize)/float64(maxKeysize)))
	upper := sizedPayloadSize/minKeysize

	minWaste := math.MaxInt64
	for n:=lower;n<=upper;n++ {
		keysize := (sizedPayloadSize-rsa.ELength) / n
		if wasted := waste(n, keysize, sizedPayloadSize); wasted < minWaste {
			minWaste = wasted
			selectedKeySize = keysize
			selectedN = n
		}
	}

	return
}

// waste calculates the amount of wasted space inside the packet
func waste(n,k, p int)int{
	h, _ := channelHash(nil)
	r := rsa.GetMaxOEAPPayloadTakenSpace(h)
	// add 1 to n because there is an extra key size payload for the public key
	unusedSapce := p-((n+1)*k+rsa.ELength)
	oaepTakenSpace := (n)*r
	publicKey := rsa.GetScheme().GetMarshalWireLength(k)
	return unusedSapce + oaepTakenSpace + publicKey
}

// numFields calculates the number of individual encrypted fields will be used
func numFields(p,k int)int{
	return p/k-1
}

func calculateRsaToPublicPacketSize(keysize, numSubPayloads int)int {
	return keysize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keysize)
}

func calculateRsaToPrivatePacketSize(keysize, numSubPayloads int)int {
	return keysize*numSubPayloads
}
