package channel

// NOTE: DO NOT CHANGE! THIS WILL RESULT IN CRYPTOGRAPHIC CHANGING PEOPLE'S
// IDENTITIES
var honorificsDefsV0 = []hd{
	{"this", 1000},
	{"", 100},
	{"that", 1000},
	{"our", 100},
	{"in", 100},
	{"the", 400},
	{"my", 1000},
	{"dr", 100},
	{"lord", 50},
	{"sir", 75},
	{"gentleman", 300},
	{"excellency", 20},
	{"theHonorable", 20},
	{"president", 10},
	{"master", 100},
	{"warden", 100},
	{"regent", 25},
	{"duke", 25},
	{"director", 80},
	{"eminence", 20},
	{"elder", 40},
	{"king", 10},
	{"queen", 10},
	{"emperor", 1},
	{"tzar", 1},
	{"overlord", 1},
	{"private", 750},
	{"corporal", 500},
	{"sergeant", 300},
	{"lieutenant", 200},
	{"captain", 100},
	{"major", 75},
	{"colonel", 50},
	{"general", 25},
	{"admiral", 25},
	{"10xDeveloper", 1},
}

var engHonorifics = compileHonorifics(honorificsDefsV0)

type hd struct {
	h         string
	frequency int
}

func compileHonorifics(defs []hd) []string {

	// precalculate the size to avoid constant reallocation
	numHonorifics := 0
	for i := range defs {
		numHonorifics += defs[i].frequency
	}

	engHonor := make([]string, 0, numHonorifics)

	defer func() []string { return engHonor }()

	for i := range defs {
		for j := 0; j < defs[i].frequency; j++ {
			engHonor = append(engHonor, defs[i].h)
		}
	}

	return engHonor
}
