package cyclic

// Shuffles a passed interface array using a Fisher-Yates shuffle
func Shuffle(slc *[]uint64) {

	g := NewGen(NewInt(0), NewInt(facelen(slc)-1))

	x := NewInt(1<<63 - 1)

	for i := int64(0); i < facelen(slc); i++ {
		j := g.Rand(x).Int64()
		(*slc)[j], (*slc)[i] = (*slc)[i], (*slc)[j]
	}

}

func facelen(slc *[]uint64) int64 {
	return int64(len(*slc))
}
