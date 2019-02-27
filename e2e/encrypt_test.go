package e2e

import (
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"testing"
)

func TestEncrypt(t *testing.T) {
	p := cyclic.NewInt(1000000010101111111)
	s := cyclic.NewInt(192395897203)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	g := cyclic.NewInt(5)
	rng := cyclic.NewRandom(min, max)
	grp := cyclic.NewGroup(p, s, g, rng)

	key := cyclic.NewInt(258063489345)
	msg := cyclic.NewInt(258063489345)

	encMsg, err := Encrypt(grp, key, msg)

	fmt.Println(&encMsg)
	fmt.Println(err)

	if err == nil {
		t.Errorf("TestEncrypt() returned an error\n\treceived: %v\n\texpected: %v", err, nil)
	}
}
