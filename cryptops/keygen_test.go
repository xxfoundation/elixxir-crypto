package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestGenerateSharedKey(t *testing.T) {
	g := cyclic.NewGroup(cyclic.NewInt(7919), cyclic.NewInt(55), cyclic.NewInt(33), cyclic.NewRandom(cyclic.NewInt(0), cyclic.NewInt(1000)))

	outRecursiveKey := cyclic.NewMaxInt()
	outSharedKey := cyclic.NewMaxInt()

	GenerateSharedKey(1024, &g, cyclic.NewInt(78), cyclic.NewInt(90), outRecursiveKey, outSharedKey)
	println(outRecursiveKey.Text(16), outSharedKey.Text(16))

	t.Error("Test implementation not finished")
}
