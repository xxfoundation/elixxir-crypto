package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestGenerateSharedKey(t *testing.T) {
	g := cyclic.NewGroup(cyclic.NewIntFromString("68636564122675662743823714992884378001308422399791648446212449933215410614414642667938213644208420192054999687", 10), cyclic.NewInt(55), cyclic.NewInt(33), cyclic.NewRandom(cyclic.NewInt(0), cyclic.NewInt(1000)))

	secretSeedKey := cyclic.NewIntFromString(
		"ef9ab83927cd2349f98b1237889909002b897231ae9c927d1792ea0879287ea3", 16)

	println("ssk bitlen:", secretSeedKey.BitLen())
	outSharedKey := cyclic.NewMaxInt()

	baseKey := cyclic.NewIntFromString(
		"da9f8137821987b978164932015c105263ae769310269b510937c190768e2930", 16)

	println("bk bitlen:", baseKey.BitLen())

	// Shared key is generated from an 8192-bit key
	println("Before:", secretSeedKey.Text(16), outSharedKey.Text(16))
	GenerateSharedKey(8192, &g, baseKey, secretSeedKey, outSharedKey)
	println("After:", secretSeedKey.Text(16), outSharedKey.Text(16))

	t.Error("Test implementation not finished")
}
