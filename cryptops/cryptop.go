package cryptops

type Cryptop interface {
	GetName() string
	GetMinSize() uint32
}
