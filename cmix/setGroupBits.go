package cmix

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
)

// SetGroupBits takes a message and a cyclic group and randomly sets
// the highest order bit in its 2 sub payloads, defaulting to 0 if 1
// would put the sub-payload outside of the cyclic group.
//
// WARNING: the behavior above results in 0 vs 1 biasing. in general, groups
// used have many (100+) leading 1s, which as a result would cause
// a bias of ~ 1:(1-2^-numLeadingBits). with a high number of leading bits,
// this is a non issue, but if a prime is chosen with few or no leading bits,
// this will cease to solve the tagging attack it is meant to fix
//
// Tagging attack: if the dumb solution of leaving the first bits as 0 is
// chosen, it is possible for an attacker to 75% of the time (when one or
// both leading bits flip to 1) identity a message they made multiplied
// garbage into for a tagging attack. This fix makes the leading its
// random in order to thwart that attack
func SetGroupBits(msg format.Message, grp *cyclic.Group, rng csprng.Source)format.Message{
	primeBytes := grp.GetP().Bytes()
	groupBitA := SelectGroupBit(msg.GetPayloadA(), primeBytes, rng)
	groupBitB := SelectGroupBit(msg.GetPayloadB(), primeBytes, rng)
	msg.SetGroupBits(groupBitA,groupBitB)
	return msg
}

const byteMask = 0b01111111

// selectGroupBit selects what the "group bit" (the highest
// order bit in the payload) should be it will randomly
// choose 1 or 0 in the event that choosing 1 will keep the payload
// in the group, otherwise it will default to 0.
// true  - set the bit to 1
// false - set the bit to 0
func SelectGroupBit(payload, prime []byte, rng csprng.Source)bool{
	//set the first bit so we can see if when the first bit is 1, if it is in the group
	payload[0] |= 0b10000000
	defer func (){
		// revert the chage on return. slices are passed by reference, so the
		// edit impacts the caller
		payload[0] &= 0b01111111
	}()

	//check if it is in the group
	if csprng.InGroup(payload, prime){
		//if it is, randomly set the first bit
		b := []byte{0}
		i, err := rng.Read(b)
		if i!=1 || err!=nil{
			jww.FATAL.Panicf("Failed to read from rng in selectGroupBit")
		}
		return b[0]>byteMask

	}else{
		//if it isnt,
		return false
	}

}
