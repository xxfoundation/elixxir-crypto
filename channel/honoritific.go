package channel

// NOTE: DO NOT CHANGE! THIS WILL RESULT IN CRYPTOGRAPHIC CHANGING PEOPLE'S
// IDENTITIES
var honorificsDefsV0 = []hd{
	{"Mr",1000},
	{"Ms",1000},
	{"one",1000},
	{"a",1000},
	{"their",1000	},
	{"its",1000},
	{"junior",500},
	{"jr",500},
	{"senior",250},
	{"sr",250},
	{"rookie",1000},
	{"deputy",250},
	{"novice",500},
	{"newbie",500},
	{"recruit",500},
	{"freshie",500},
	{"apprentice",1000},
	{"fledgeling",500},
	{"neophyte",50},
	{"1stMate",100},
	{"2ndMate",200},
	{"brother",750},
	{"sister",750},
	{"this",1000},
	{"aCertain",500},
	{"aParticular",500},
	{"aWellKnown",500},
	{"",500},
	{"your",1000},
	{"that",1000},
	{"our",500},
	{"in",100},
	{"the",900},
	{"my",1000},
	{"dr",100},
	{"mc",1000},
	{"dj",1000},
	{"lord",50},
	{"sir",200},
	{"madam",200},
	{"gentleman",300},
	{"coach",500},
	{"inspector",300},
	{"lady",300},
	{"theExcellency",20},
	{"councillor",100},
	{"consul",50},
	{"alderman",50},
	{"magistrate",50},
	{"judge",50},
	{"meistro",200},
	{"mayor",250},
	{"theHonorable",20},
	{"premier",20},
	{"primarch",20},
	{"prime minister",11},
	{"president",10},
	{"master",100},
	{"warden",100},
	{"regent",50},
	{"baron",75},
	{"baroness",75},
	{"duchess ",25},
	{"duke",25},
	{"inquisiotor",50},
	{"director",80},
	{"theVenerable",80},
	{"hisEminence",20},
	{"herEminence",20},
	{"elder",40},
	{"prince",80},
	{"princess",80},
	{"king",10},
	{"queen",10},
	{"emperor",1},
	{"empress",1},
	{"tzar",1},
	{"overlord",1},
	{"super",1},
	{"private",750},
	{"corporal",500},
	{"sergeant",300},
	{"lieutenant",200},
	{"captain",100},
	{"major",75},
	{"colonel",50},
	{"general",25},
	{"admiral",25},
	{"dunce",1},
	{"10xDeveloper",1},
	{"senpai",1},
	{"gymLeader",2},
	{"leagueChampion",1},
	{"jedi",1},
	{"darth",1},
	{"x",1},
	{"xXx",1},
	{"spectre",1},
	{"theGreatAndPowerfull",1},
	{"sparkle",1},
	{"super",1},
	{"1337hax0r",1},
	{"bullshitArtist",1},
	{"chiefEngineer",5},
	{"chief",300},
	{"boss",200},
	{"don",50},
	{"monsieur",300},
	{"madame",300},
	{"mistress",300},
	{"padre",300},
	{"patron",100},
	{"senor",400},
	{"senora",400},
	{"tio",200},
	{"tia",200},
	{"uncle",200},
	{"aunt",200},
	{"senorita",300},
	{"jefe",200},
	{"herr",200},
	{"chef",50},
	{"monarch",15},
	{"sultan",10},
	{"chancellor",100},
	{"elector",200},
	{"oldman",500},
	{"stormtrooper",2},
	{"adept",200},
	{"archon",1},
	{"centurion ",100},
	{"commissar",75},
	{"praetor",100},
	{"seer",100},
	{"ambassador",200},
	{"constable",250},
	{"representative",400},
	{"scriptKiddie",50},
	{"scriptKitty",10},
	{"codeMonkey",25},
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
