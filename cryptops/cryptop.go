package cryptops

type Cryptop interface {
	GetName() string
	GetInputSize() uint32
}
