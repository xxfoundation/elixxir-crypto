package cyclic

// Shuffles a passed interface array using a Fisher-Yates shuffle
func Shuffle(slice *[]uint64) {

	g := NewGen(NewInt(0), NewInt(facelen(slice)-1))

	x := NewInt(1<<63 - 1)

	for i := int64(0); i < facelen(slice); i++ {
		j := g.Rand(x).Int64()
		(*slice)[j], (*slice)[i] = (*slice)[i], (*slice)[j]
	}

}

func facelen(slice *[]uint64) int64 {
	return int64(len(*slice))
}
