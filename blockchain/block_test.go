////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package blockchain

import (
	"fmt"
	"gitlab.com/elixxir/crypto/coin"
	"math/rand"
	"reflect"
	"testing"
)

//Shoes that the origin block is valid
func TestGenerateOriginBlock(t *testing.T) {
	b := GenerateOriginBlock()

	if reflect.DeepEqual(*b, Block{}) {
		t.Errorf("GenerateOriginBlock: Origin Block returned is empty: %v", b)
	}

	if reflect.DeepEqual(b.hash, BlockHash{}) {
		t.Errorf("GenerateOriginBlock: Origin Block returned empty hash: %v", b)
	}

	if b.id != 0 {
		t.Errorf("GenerateOriginBlock: Origin Block has wrong block ID: %v", b.id)
	}
}

//Shows that the output of Nextblock is the correct lifecycle and only activates with the correct lifecycle
func TestBlock_NextBlock_Lifecycle(t *testing.T) {
	ob := GenerateOriginBlock()

	b, err := ob.NextBlock()

	if err != nil {
		t.Errorf("Block.NextBlock: Errored with valid lifecycle state: %v", b)
	}

	ob.lifecycle = Raw

	_, err = ob.NextBlock()

	if err != ErrBaked {
		if err == nil {
			t.Errorf("Block.NextBlock: Returned no error with invalid lifecycle state")
		} else {
			t.Errorf("Block.NextBlock: Returned incorrect error with invalid lifecycle state: %s", err.Error())
		}
	}

	if b.lifecycle != Raw {
		t.Errorf("Block.NextBlock: Returned block with incorrect lifecycle state: %v", b.lifecycle)
	}
}

//Shows the NextBlock increments the id properly
func TestBlock_NextBlock_BlockID(t *testing.T) {
	var err error
	b := GenerateOriginBlock()

	for i := uint64(0); i < uint64(100); i++ {
		if b.id != i {
			t.Errorf("Block.NextBlock: Block ID %v incorrect, reads as: %v", i, b.id)
		}
		b.lifecycle = Baked
		b, err = b.NextBlock()
		if err != nil {
			t.Errorf("Block.NextBlock: error on valid block creation: %s", err.Error())
		}
	}
}

//Shows that the output of NextBlock hash the correct previous Hash
func TestBlock_NextBlock_PreviousHash(t *testing.T) {
	ob := Block{}
	ob.lifecycle = Baked
	ob.hash[0] = 69

	nb, err := ob.NextBlock()

	if err != nil {
		t.Errorf("Block.NextBlock: Errored with valid block creation: %s", err.Error())
	}

	if !reflect.DeepEqual(ob.hash, nb.previousHash) {
		t.Errorf("Block.NextBlock: Returne block does not have correct previous hash: Expected: %v, Recieved; %v",
			ob.hash, nb.previousHash)
	}
}

//Shows that get created returns the created list and that it is a copy
func TestBlock_GetCreated(t *testing.T) {
	src := rand.NewSource(42)

	prng := rand.New(src)

	block := Block{}

	//build a created list
	for i := uint64(0); i < 50; i++ {
		value := (prng.Uint64() % (coin.MaxValueDenominationRegister - 1)) + 1

		seed, err := coin.NewSeed(value)

		if err != nil {
			t.Errorf("Block.GetCreated: Error on creation of seed: %s", err.Error())
		}
		compound := seed.ComputeCompound()
		coins := compound.ComputeCoins()
		block.created = append(block.created, coins...)
	}

	recievedCreated := block.GetCreated()

	if !reflect.DeepEqual(block.created, recievedCreated) {
		t.Errorf("Block.GetCreated: returned created coins not equal to real created coins: "+
			"First Expected: %v, First Recieved: %v", block.created[0], recievedCreated[0])
	}

	recievedCreated[0][0] = ^recievedCreated[0][0]

	if reflect.DeepEqual(block.created, recievedCreated) {
		t.Errorf("Block.GetCreated: editing created coins edits coins in chain!")
	}
}

//Shows that add created adds coins and only works when Raw
func TestBlock_AddCreated(t *testing.T) {
	block := Block{}
	block.lifecycle = Raw

	c := coin.Coin{}
	c[0] = 42

	err := block.AddCreated([]coin.Coin{c})

	if err != nil {
		t.Errorf("Block.AddCreated: error occured when lifecycle is correct: %s", err.Error())
	}

	if len(block.created) != 1 {
		t.Errorf("Block.AddCreated: created list zero length after added coin: %v", block.created)
	}

	if !reflect.DeepEqual(c, block.created[0]) {
		t.Errorf("Block.AddCreated: coin in block not equal to coin added: "+
			"Added: %v, Recieved: %v", c, block.created[0])
	}

	block.lifecycle = Baked

	c2 := coin.Coin{}
	c2[0] = 69

	err = block.AddCreated([]coin.Coin{c})

	if err != ErrRaw {
		if err == nil {
			t.Errorf("Block.AddCreated: no error occured when lifecycle is incorrect")
		} else {
			t.Errorf("Block.AddCreated: incorrect error occured when lifecycle is incorrect: %s", err.Error())
		}
	}

	if len(block.created) != 1 {
		t.Errorf("Block.AddCreated: created list not a length of one after added coin: %v", block.created)
	}
}

//Shows that get destroyed returns the created list and that it is a copy
func TestBlock_GetDestroyed(t *testing.T) {
	src := rand.NewSource(42)

	prng := rand.New(src)

	block := Block{}

	//build a created list
	for i := uint64(0); i < 50; i++ {
		value := (prng.Uint64() % (coin.MaxValueDenominationRegister - 1)) + 1

		seed, err := coin.NewSeed(value)

		if err != nil {
			t.Errorf("Block.GetDestroyed: Error on creation of seed: %s", err.Error())
		}
		compound := seed.ComputeCompound()
		coins := compound.ComputeCoins()
		block.destroyed = append(block.destroyed, coins...)
	}

	recievedDestroyed := block.GetDestroyed()

	if !reflect.DeepEqual(block.destroyed, recievedDestroyed) {
		t.Errorf("Block.GetDestroyed: returned destroyed coins not equal to real destroyed coins: "+
			"First Expected: %v, First Recieved: %v", block.destroyed[0], recievedDestroyed[0])
	}

	recievedDestroyed[0][0] = ^recievedDestroyed[0][0]

	if reflect.DeepEqual(block.destroyed, recievedDestroyed) {
		t.Errorf("Block.GetDestroyed: editing destroyed coins edits coins in chain!")
	}
}

//Shows that add destroyed adds coins and only works when Raw
func TestBlock_AddDestroyed(t *testing.T) {
	block := Block{}
	block.lifecycle = Raw

	c := coin.Coin{}
	c[0] = 42

	err := block.AddDestroyed([]coin.Coin{c})

	if err != nil {
		t.Errorf("Block.AddDestroyed: error occured when lifecycle is correct: %s", err.Error())
	}

	if len(block.destroyed) != 1 {
		t.Errorf("Block.AddDestroyed: destroyed list zero length after added coin: %v", block.created)
	}

	if !reflect.DeepEqual(c, block.destroyed[0]) {
		t.Errorf("Block.AddDestroyed: coin in block not equal to coin added: "+
			"Added: %v, Recieved: %v", c, block.destroyed[0])
	}

	block.lifecycle = Baked

	c2 := coin.Coin{}
	c2[0] = 69

	err = block.AddDestroyed([]coin.Coin{c})

	if err != ErrRaw {
		if err == nil {
			t.Errorf("Block.AddDestroyed: no error occured when lifecycle is incorrect")
		} else {
			t.Errorf("Block.AddDestroyed: incorrect error occured when lifecycle is incorrect: %s", err.Error())
		}
	}

	if len(block.destroyed) != 1 {
		t.Errorf("Block.AddDestroyed: destroyed list not a length of one after added coin: %v", block.created)
	}
}

// Shows that GetHash returns a valid copy of the hash
func TestBlock_GetHash(t *testing.T) {
	b := Block{}

	b.hash[0] = 42
	b.lifecycle = Raw

	_, err := b.GetHash()

	if err != ErrBaked {
		if err == nil {
			t.Errorf("Block.GetHash: No error returned when not baked")
		} else {
			t.Errorf("Block.GetHash: Incorrect error returned when not baked: %s", err.Error())
		}
	}

	b.lifecycle = Baked

	hashCopy, err := b.GetHash()

	if err != nil {
		t.Errorf("Block.GetHash: Error returned on valid call: %s", err.Error())
	}

	if !reflect.DeepEqual(b.hash, hashCopy) {
		t.Errorf("Block.GetHash: returned hash not equal to stored hash: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}

	hashCopy[0] = 69

	if reflect.DeepEqual(b.hash, hashCopy) {
		t.Errorf("Block.GetHash: editing returned hash modifies stored hash: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}
}

// Shows that GetPreviousHash returns a valid copy of the hash
func TestBlock_GetPreviousHash(t *testing.T) {
	b := Block{}

	b.previousHash[0] = 42

	hashCopy := b.GetPreviousHash()

	if !reflect.DeepEqual(b.previousHash, hashCopy) {
		t.Errorf("Block.GetPreviousHash: returned hash not equal to stored hash: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}

	hashCopy[0] = 69

	if reflect.DeepEqual(b.previousHash, hashCopy) {
		t.Errorf("Block.GetPreviousHash: editing returned hash modifies stored hash: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}
}

// Shows that GetLifecycle returns the correct Lifecycle state
func TestBlock_GetLifecycle(t *testing.T) {
	b := Block{}

	b.lifecycle = Raw

	if b.GetLifecycle() != Raw {
		t.Errorf("Block.GetLifecycle: Did not return a lifecycle of Raw: %v", b.GetLifecycle())
	}

	b.lifecycle = Baked

	if b.GetLifecycle() != Baked {
		t.Errorf("Block.GetLifecycle: Did not return a lifecycle of Baked: %v", b.GetLifecycle())
	}
}

// Shows that GetID returns the correct Block ID state
func TestBlock_GetID(t *testing.T) {
	b := Block{}

	expectedBlockID := uint64(42)

	b.id = expectedBlockID

	if b.GetID() != expectedBlockID {
		t.Errorf("Block.GetID: Did not return the correct ID: Expected: %v, Recieved: %v", expectedBlockID, b.GetID())
	}
}

// Shows that GetTreeRoot only works when the state is correct and responds properly
func TestBlock_GetTreeRooth(t *testing.T) {
	b := Block{}

	b.treeRoot[0] = 42
	b.lifecycle = Raw

	_, err := b.GetTreeRoot()

	if err != ErrBaked {
		if err == nil {
			t.Errorf("Block.GetTreeRoot: No error returned when not baked")
		} else {
			t.Errorf("Block.GetTreeRoot: Incorrect error returned when not baked: %s", err.Error())
		}
	}

	b.lifecycle = Baked

	hashCopy, err := b.GetTreeRoot()

	if err != nil {
		t.Errorf("Block.GetTreeRoot: Error returned on valid call: %s", err.Error())
	}

	if !reflect.DeepEqual(b.treeRoot, hashCopy) {
		t.Errorf("Block.GetTreeRoot: returned root not equal to stored root: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}

	hashCopy[0] = 69

	if reflect.DeepEqual(b.treeRoot, hashCopy) {
		t.Errorf("Block.GetTreeRoot: editing returned root modifies stored root: Stored: %v, Returned: %v",
			b.hash, hashCopy)
	}
}

//TODO: Tests of Bake's cryptographic properties
//Shows that bake works only with the correct lifecycle and it returns the correct lifecycle
func TestBlock_Bake(t *testing.T) {
	b := Block{}

	b.lifecycle = Raw

	b.AddCreated([]coin.Coin{{}})
	b.AddDestroyed([]coin.Coin{{}})

	trExpected := BlockHash{}
	trExpected[0] = 99

	err := b.Bake([]coin.Seed{{}}, trExpected)

	if err != nil {
		t.Errorf("Block.Bake: Could not bake with valid lifecycle: %s", err.Error())
	}

	if b.lifecycle != Baked {
		t.Errorf("Block.Bake: bake did not set the lifecycle to baked")
	}

	if !reflect.DeepEqual(b.treeRoot, trExpected) {
		t.Errorf("Block.Bake: Stored tree root not the same as given tree root: Given: %v, Stored: %v",
			trExpected, b.treeRoot)
	}

	err = b.Bake([]coin.Seed{{}}, BlockHash{})

	if err != ErrRaw {
		if err == nil {
			t.Errorf("Block.Bake: no error retruned when baking a block at the wrong lifecycle")
		} else {
			t.Errorf("Block.Bake: incorrect error retruned when baking a block at the wrong lifecycle: %s",
				err.Error())
		}
	}

}

//Test that Serialize and Deseralize work correctly
func TestBlock_SerializeDeserialize(t *testing.T) {

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

	trExpected := BlockHash{}
	trExpected[0] = 99

	err = block.Bake(seedList, trExpected)

	if err != nil {
		t.Errorf("Block.Serialize: Error on bake: %s", err.Error())
	}

	serial, err := block.Serialize()
	if err != nil {
		t.Errorf("Block.Serialize: Error on serialization: %s", err.Error())
	}

	fmt.Printf("Test Block: %s\n", string(serial))

	newBlock, err := Deserialize(serial)

	if err != nil {
		t.Errorf("Block.Deseralize: Error on valid deseralization: %s", err.Error())
	}

	if !reflect.DeepEqual(block, newBlock) {
		t.Errorf("Block.Deseralize/Block.Serialize: Deseralized block does not match Origonal Block")
	}

	if !reflect.DeepEqual(block.hash, newBlock.hash) {
		t.Errorf("Block.Deseralize/Block.Serialize: Deseralized hash does not match Origonal hash: "+
			"Origonal Hash: %v, Serial Hash: %v", block.hash, newBlock.hash)
	}

	if !reflect.DeepEqual(block.previousHash, newBlock.previousHash) {
		t.Errorf("Block.Deseralize/Block.Serialize: Deseralized previous hash does not match Origonal previous hash: "+
			"Origonal Hash: %v, Serial Hash: %v", block.previousHash, newBlock.previousHash)
	}

	if !reflect.DeepEqual(block.created[0], newBlock.created[0]) {
		t.Errorf("Block.Deseralize/Block.Serialize: Deseralized first crreated coin does not match Origonal first crreated coin: "+
			"Origonal Coin: %v, Serial Coin: %v", block.created[0], newBlock.created[0])
	}

	if !reflect.DeepEqual(block.destroyed[0], newBlock.destroyed[0]) {
		t.Errorf("Block.Deseralize/Block.Serialize: Deseralized first destroyed coin does not match Origonal first destroyed coin: "+
			"Origonal Coin: %v, Serial Coin: %v", block.destroyed[0], newBlock.destroyed[0])
	}
}

func TestBlock_Serialize_Lifecycle(t *testing.T) {
	b := Block{}

	b.lifecycle = Raw
	b.created = []coin.Coin{{}}
	b.destroyed = []coin.Coin{{}}
	b.treeRoot[0] = 42

	_, err := b.Serialize()

	if err != ErrBaked {
		if err == nil {
			t.Errorf("Block.Serialize: no error returned on invalid lifecycle")
		} else {
			t.Errorf("Block.Serialize: Incorrect error returned on invalid lifecycle: %s", err.Error())
		}
	}

	b.lifecycle = Baked

	_, err = b.Serialize()

	if err != nil {
		t.Errorf("Block.Serialize: error returned on valid serialization")
	}
}

func TestDeserialize(t *testing.T) {
	_, err := Deserialize([]byte{})

	if err == nil {
		t.Errorf("Deserialize: no error returned on invalid deseralization")
	}

}
