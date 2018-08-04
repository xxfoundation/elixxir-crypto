package blockchain

import (
	"fmt"
	"gitlab.com/privategrity/crypto/coin"
	"math/rand"
	"reflect"
	"testing"
)

//
func TestGenerateOriginBlock(t *testing.T) {
	b := GenerateOriginBlock()

	if reflect.DeepEqual(*b, Block{}) {
		t.Errorf("GenerateOriginBlock: Origin Block returned is empty: %v", b)
	}

	if reflect.DeepEqual(b.hash, BlockHash{}) {
		t.Errorf("GenerateOriginBlock: Origin Block returned empty hash: %v", b)
	}
}

func TestBlock_NextBlock_Lifecycle(t *testing.T) {
	ob := GenerateOriginBlock()

	b, err := ob.NextBlock()

	if err != nil {
		t.Errorf("Block.NextBlock: Errored with valid lifecycle state: %v", b)
	}
}

func TestBlock_Serialize(t *testing.T) {

	src := rand.NewSource(42)

	prng := rand.New(src)

	sum := uint64(0)

	block, err := GenerateOriginBlock().NextBlock()

	if err != nil {
		t.Errorf("Block.Serialize: Error on creation of block: %s", err.Error())
	}

	var seedList []coin.Seed

	//make coins to create
	for i := uint64(0); i < 50; i++ {
		value := (prng.Uint64() % (coin.MaxValueDenominationRegister - 1)) + 1
		sum += value

		seed, err := coin.NewSeed(value)

		if err != nil {
			t.Errorf("Block.Serialize: Error on creation of seed: %s", err.Error())
		}

		seedList = append(seedList, seed)

		compound := seed.ComputeCompound()
		coins := compound.ComputeCoins()
		block.AddCreated(coins)
	}

	sum2 := uint64(0)

	for sum2 < sum {
		value := (prng.Uint64() % (coin.MaxValueDenominationRegister - 1)) + 1
		sum2 += value

		if sum2 >= sum {
			value = sum - (sum2 - value)
			sum2 = sum
		}

		seed, err := coin.NewSeed(value)

		if err != nil {
			t.Errorf("Block.Serialize: Error on creation of seed: %s", err.Error())
		}

		seedList = append(seedList, seed)
		compound := seed.ComputeCompound()
		coins := compound.ComputeCoins()

		block.AddDestroyed(coins)
	}

	block.Bake(seedList)

	serial, err := block.Serialize()
	if err != nil {
		t.Errorf("Block.Serialize: Error on serialization: %s", err.Error())
	}

	fmt.Println(string(serial))
}
