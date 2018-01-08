package cyclic

// Shuffles a passed interface array using a Fisher-Yates shuffle
func Shuffle(slice *[]uint64) {

	g := NewGen(NewInt(0), NewInt(int64(len(*slice))-1))

	x := NewInt(1<<63 - 1)

	for curPos := int64(0); curPos < int64(len(*slice)); curPos++ {
		randPos := g.Rand(x).Int64()
		(*slice)[randPos], (*slice)[curPos] = (*slice)[curPos], (*slice)[randPos]
	}

}
