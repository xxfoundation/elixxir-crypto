package blockchain

import (
	"crypto/sha256"
	"encoding/json"
	"gitlab.com/privategrity/crypto/coin"
	"gitlab.com/privategrity/crypto/shuffle"
	"sync"
)

const BlockHashLenBits = 256
const BlockHashLen = BlockHashLenBits / 8

type BlockHash [BlockHashLen]byte

type Block struct {
	hash         BlockHash
	previousHash BlockHash
	created      []coin.Coin
	destroyed    []coin.Coin
	lifecycle    BlockLifecycle
	mutex        sync.Mutex
}

type serialBlock struct {
	Hash         []byte
	PreviousHash []byte
	Created      [][]byte
	Destroyed    [][]byte
}

func GenerateOriginBlock() *Block {
	b := Block{lifecycle: Raw}

	b.created = append(b.created, coin.Coin{})
	b.destroyed = append(b.destroyed, coin.Coin{})

	b.Bake([]coin.Seed{coin.Seed{}})

	return &b
}

func (b *Block) NextBlock() (*Block, error) {
	b.mutex.Lock()
	if b.lifecycle != Baked {
		b.mutex.Unlock()
		return &Block{}, ErrBaked
	}

	newBlock := Block{}

	copy(newBlock.previousHash[:], b.hash[:])

	b.mutex.Unlock()

	return &newBlock, nil
}

func (b *Block) GetCreated() []coin.Coin {
	b.mutex.Lock()
	cCopy := make([]coin.Coin, len(b.created))
	copy(cCopy, b.created)
	b.mutex.Unlock()
	return cCopy
}

func (b *Block) AddCreated(c []coin.Coin) error {
	b.mutex.Lock()
	if b.lifecycle != Raw {
		b.mutex.Unlock()
		return ErrRaw
	}

	b.created = append(b.created, c...)

	b.mutex.Unlock()

	return nil
}

func (b *Block) GetDestroyed() []coin.Coin {
	b.mutex.Lock()
	cCopy := make([]coin.Coin, len(b.destroyed))
	copy(cCopy, b.destroyed)
	b.mutex.Unlock()
	return cCopy
}

func (b *Block) AddDestroyed(c []coin.Coin) error {
	b.mutex.Lock()
	if b.lifecycle != Raw {
		b.mutex.Unlock()
		return ErrRaw
	}

	b.destroyed = append(b.destroyed, c...)

	b.mutex.Unlock()

	return nil
}

func (b *Block) GetHash() BlockHash {
	var rtnBH BlockHash
	b.mutex.Lock()
	copy(rtnBH[:], b.hash[:])
	b.mutex.Unlock()
	return rtnBH
}

func (b *Block) GetPreviousHash() BlockHash {
	var rtnBH BlockHash
	b.mutex.Lock()
	copy(rtnBH[:], b.previousHash[:])
	b.mutex.Unlock()
	return rtnBH
}

func (b *Block) Bake(seedList []coin.Seed) error {
	b.mutex.Lock()

	if b.lifecycle != Raw {
		b.mutex.Unlock()
		return ErrRaw
	}

	//Shuffle the elements
	rawSeed := seedlistToSlice(seedList)
	shuffle.ShufflePRNG(rawSeed, len(b.created), func(i, j int) {
		b.created[i], b.created[j] = b.created[j], b.created[i]
	})
	//Hash the seed used for the destroy elements so the two lists aren't shuffled the same way
	hb := sha256.New()
	hb.Write(rawSeed)
	destroySeed := hb.Sum(nil)
	shuffle.ShufflePRNG(destroySeed, len(b.destroyed), func(i, j int) {
		b.destroyed[i], b.destroyed[j] = b.destroyed[j], b.destroyed[i]
	})

	//Hash the elements
	h := sha256.New()
	h.Write(b.previousHash[:])
	h.Write(coinlistToSlice(b.created))
	h.Write(coinlistToSlice(b.destroyed))
	hashBytes := h.Sum(nil)

	copy(b.hash[:BlockHashLen], hashBytes[:BlockHashLen])

	//Set the lifecycle to baked
	b.lifecycle = Baked

	b.mutex.Unlock()
	return nil
}

func (b *Block) Serialize() ([]byte, error) {
	if b.lifecycle != Baked {
		return []byte{}, ErrBaked
	}

	pb := serialBlock{
		Hash:         b.hash[:],
		PreviousHash: b.previousHash[:],
	}

	for indx := range b.created {
		pb.Created = append(pb.Created, b.created[indx][:])
	}

	for indx := range b.destroyed {
		pb.Destroyed = append(pb.Destroyed, b.destroyed[indx][:])
	}

	return json.Marshal(pb)
}

//Private Helper Functions

func seedlistToSlice(seedList []coin.Seed) []byte {
	var outBytes []byte

	for _, s := range seedList {
		outBytes = append(outBytes, s[:]...)
	}

	return outBytes
}

func coinlistToSlice(coinList []coin.Coin) []byte {
	var outBytes []byte

	for _, c := range coinList {
		outBytes = append(outBytes, c[:]...)
	}

	return outBytes
}
