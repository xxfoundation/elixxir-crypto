////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
)

func TestConstructIdentity(t *testing.T) {
	numtests := 100

	rng := &csprng.SystemRNG{}
	codenames := make([]string, 0, numtests)

	for i := 0; i < numtests; i++ {
		id, _ := GenerateIdentity(rng)
		codenames = append(codenames, id.Codename+"#"+id.Extension+
			id.Color)
	}

	for i := 0; i < numtests; i++ {
		for j := i + 1; j < numtests; j++ {
			if codenames[i] == codenames[j] {
				t.Errorf("2 generated codenames are the same, %d vs %d",
					i, j)
			}
		}
	}
}

func TestConstructIdentity_Vector(t *testing.T) {
	numtests := 100

	rng := rand.New(rand.NewSource(42))
	codenames := make([]string, 0, numtests)
	expectedCodeNames := []string{
		"thisDownPruriency#CJBQ1Z7JR7B92gVvitmJbuzyQLOIHm0x77BFC7",
		"mrDisruptiveEpiphysis#diTJfbO4VEdjfsRZ78Lw46mG5B4s3Y0x57FEFF",
		"herNeriticPlunger#eyrYJ5rkz2S0geIaKRxlhVtMd1lzvg0x57FEFF",
		"deputyUndueSturdiness#IGXyptJWwIEvodXOQelrok5/I+d6Wv0xFFE87C",
		"brotherNorthAmericanDebauch#JHfoarwsvjQMY5iZypfxQPBoa+US3T0xFDEEF4",
		"fledgelingPeltateHelpmate#J7sDlY7bHn8Iu3XPte6pga5ZaWLfT20xF6358A",
		"theVenerableFeatherlikeCemetery#y8mnzmlzQVUMPgMByUtpV1X8HNdp/m0x56A5EC",
		"herUndoableUnquestionableness#0OQddD1SY9IOyfoFDtGXquChG/kCXt0xE18B6B",
		"yourUnwoundedPortiere#VQB+elebg54sG1o9AyzDiSDIGKo6S70xB041FF",
		"chiefGrilledCasuariiformes#u0P0nkNbHDMHi12fwtSISDW3wxEBDs0xC5908E",
		"apprenticeLonghandCeratitis#iIvJy9nuiJg7H3TLwumyN37vtTrdr60xE238EC",
		"apprenticeBasidialPonce#WtAoXbvG/Dhts/hODSvH6hDclfN33E0x57E964",
		"gentlemanHoraryLacertidae#aqhA8UEV525NUucnkHQdfymVDAL2xb0xFAAFBE",
		"chiefMulticellularRogerSessions#FIzpM5LrItNjLFZpIiMhV0rx6kqoLM0xC9BE62",
		"djFoggedCentimeter#+0kY0+W/mN9Vk8fOk536zGFu5JVi6K0xF88017",
		"mcReformistQuagga#7/U4P2FKBAaHX7CquQ3oQac1++aBY+0xB041FF",
		"brotherVotelessConqueror#G6omqBoKDTL4NFpic5P+IpuKkfbbeY0xA74AC7",
		"mcUnifoliateFulfilment#du1ojRiL7pU4Owq4o1cjK7qzYBX5tR0x4CC417",
		"madameInsectanRefectory#7IspUGfv8lFjf3j9pxI9aN2xiiQGE40x48CCCD",
		"padreFoliateBigDipper#XVECxCH7ZPU5qCsyLgnnDwmUWsT4P00xE9AB17",
		"privateCutOutAirwoman#oTPqAD4ZVfSI9u+6NnA2HBDwmoMiq20xCA226B",
		"theirIllAtEaseAfterglow#CBhMFc2S4EsMaOF361VVjJugepEEbU0xF75D59",
		"myAstylarVagrancy#UyJJFRRYjaOjJ78pQ5nMV9wxKGCSqN0xE41B17",
		"itsLxivHankering#Fx+XJnd3aongZqcaXJtAFyUYUTlYpD0xFFFC17",
		"djUnpractisedAbcoulomb#8VDrAkNQomebVKsa+BRR7+QOUtFcS10xECD672",
		"hisPyrogenicGospeler#ON7m/yKsp8nIWK3XnrT5+x+Lcv8MnP0xC7A317",
		"msUnsurprisingFemaleHorse#TQDfTRTkRtk17mC66/V5V1h6Lmxtnj0x00FFFF",
		"rookieVoraciousChiefJustice#OQIxTFPiDXuH8C5DzlQMZtblOY3v5J0xF6358A",
		"recruitAnaglyphicBullheadCatfish#1mYeBOM8W9l155FPtQrS8lO+7P7OVG0xD462FF",
		"herrDigressiveStorage#n7WfNv5sU7k14YwnKvkbSEe1Q+ZbA20xE56E94",
		"newbieHardcoreConcubine#Do33eHXNpszdIg48vxu54NJ6Z/NZLV0x5EFB6E",
		"privateUnconfirmedSetup#vZZW1mpxAHySKuVVdZg2efSi7agsrA0x43C6DB",
		"representativeNecklikeDarwinism#bMcXb1srnFLumAEvm8YxFG1TxqO2310x43BFC7",
		"jefeAniseikonicCult#aYgewQbqBlL1z+Bvd5S3sCLPptCck70xA0C544",
		"chiefClarifyingQueenOfEngland#YZN14FDNGhfrvglD2fbF4h1Wjtn9LW0x48CCCD",
		"myEntertainedQuadrilateral#8es/JqPu6qTL6N5VTwD3udCa2X5sGN0x5EFB6E",
		"noviceDepartedAscription#8GTh/1guvSfcHdg7u6+2Z6kCKHQqgD0xFFF8C6",
		"jrUntaggedFedora#gKckIJS6r+Fr5KJ7UmP+cnCgENCxVR0x57FEFF",
		"tiaDualSeaside#jKXmp0xHki2DDaYGuzrJxT3Buyw0r30xC6AEC7",
		"thatGarrulousVentHole#9iW47PUFZobB40jLa/Ircd15R9UOX40xF665AB",
		"freshiePolycrystallineGruel#AiHgclVykhE117QZLUsLDe3PyaiL//0xF75D59",
		"thatObsessiveGeorgeEdwardMoore#kOAubHhdI4YSiddHZtiaxVz5L30VQs0xE41B17",
		"theEvidentiaryTalkOfTheTown#jLoLArQEWCO0mijjlszerWYgUAp0c20xF6358A",
		"herMercerizedAster#/Ly7aeiOzDfxarK0JdB5ub/o5SJ9J+0x43BFC7",
		"itsToughenedLysin#sfuEVKCLqg0ZU2e9dpk+TowWfxDnrU0x7FE817",
		"thisPurpleRedStartOff#RhkPV4oeDc4MQJj29OdER51O1TBJJe0x52D017",
		"djFileLikeCollyrium#0SP+BRiIXUhmweMfPFhnbSENP16ZlZ0xE0FFFF",
		"herBrisantMicrocephaly#CQosQspA5p6Nmg6iIFX4fveCiZuWis0x9E7BFF",
		"ourUnspecialisedGingerAle#4CNwfPw4hQb5NuPVXwI4aAr8Ams++J0xF6358A",
		"jrDuplicatableCataclysm#EP1WyHh21rAmSUT+5aNMoJb4I6/eKb0xCA226B",
		"thePaleocorticalPalatine#nVCP1OkG2Kob462gdeFSGlpHTKNXqM0xC12283",
		"sausageShapedGoosander#s5CDyaJCyflp94Nht60BgMynfQIxt60x64E986",
		"hisAstonishedItalicLanguage#oSpGyMiORey7lqbIAcgL2H5MTWs87n0x00FFFF",
		"djPillaredTrue#/PTDWmUsAOIYm5OjO+i68maTs5ZQ320x43BFC7",
		"thisAcidoticButeaMonosperma#Ey44JvrTjZc5bw1THQ/FCjQDboixk70xEDE275",
		"thisBroadbandShortcake#CFBonykLjYHMzGESusgET+ojZXnXy+0x3EA99F",
		"baronessExpectantInsouciance#of1pNqREHIQeNV/qjtclGr1K3EZAOE0xEDDA74",
		"brotherGracileBreathing#xEn2zV0WoZowqE/anGrXEkXclKDEjm0x48CCCD",
		"mrCreepyVinylbenzene#6eNDFseaT07bWJ7XbhxUi4hadmGWkO0x3EA99F",
		"mayorApostrophicFatality#nD+VIRKJFpOVjm8jnTjLXLwkWNVHoJ0xC68E17",
		"chiefSpinousLeukemia#UcEhk455MmNyx8aZv/ninLoGk+t9+H0xC48793",
		"fledgelingManyAnotherAccusation#9ONAWOcBCb32QvAq2XAZRjt82iA7us0xC25A7C",
		"itsUnappetisingPerusal#D6DvIW4Ett7mAm9yPrqzudLYCiVqCQ0xC12267",
		"herPoundFoolishSanaa#6f+VMw9K669bzC7+Yhg+WzEg8UZWnW0xB38481",
		"jrArcticFeticide#dC3bCc9Pnum6PJ6FZbxAdaqgK/OgDa0xE18B6B",
		"mrRopeySivapithecus#t3GIfdsaml800cqHQovmhY6CapFW9V0x54C571",
		"inOpprobriousPlanking#CxgaD4atGCC2ySR1FUjbuVNEgy5aBP0x57FEFF",
		"privateMiddleElement#AosH51cvf16D7e+ngycHz1qMafxaED0xF75D59",
		"hisOtherNellieRoss#R3nMp5DTaVJ7lM7AivOpMQGfEedlPA0xB38481",
		"senoraDefendableTrainingShip#MgfelOEBdci1MYxvCFVg+GOmXYesRv0xE7A1B0",
		"thisEnoughMelampsoraceae#xET81e2mef+GNsepulMKS4qHzVNXg80x8AFB17",
		"djJocundRecognizance#cazZBzanh8y0/pH5oFsKX3kggDYUhC0x00FFFF",
		"theSurroundedPythoninae#nEax3bLPHQnUGeKB0XAKAZWKbIXrMY0x1589FF",
		"electorAnalogInebriant#VUW+i98apTF35NvwGp1jsgK1dh/pHr0xE3319D",
		"thisPapalMalignance#xm7wVal361xYnPfeQgB7LT890VRObk0xC6DEFF",
		"fledgelingMousyStopper#11ohNjlcsuclZAfIUIt84U4JwCwU2b0xFFFF00",
		"herWoollenIndirection#GVptxNdWnI5ExW1xizO/AojF17oD/90xE6A9EC",
		"hisUnrecognizedAccentuation#LUVWIV8khBXd6nZRPRaQuiHO5g0XOs0x1589FF",
		"privateKindlyBlonde#9Qv4vcwkBAvj6x6qOUyYfPP0nFKKv/0xFF0000",
		"padreHygienicalGoodForm#DPL5HrXuemKD4fTUIyxGBUBFrP4L5f0xC12267",
		"djBrisantMusicalOrganization#04XTUr4bdtfuXRlgvqHaydSoI8jrvB0x488AC7",
		"thatLadylikeAppleTree#gx3HpBXMc7pk/B1ClkJqORpl7mxjs10xF75D59",
		"privateMushyPrognostic#oxWVz57MNz1JG/JgzNusw0fAdHiq0D0xFAAFBA",
		"theirPurposelessEmbellishment#4tBa2MKTV3W6+Pgr7wuNd6GxtvQ3r/0x82CAFA",
		"msAmusiveAllusiveness#rC+WyvBvP1z2chh4caISyKtrAwGnk40xD462FF",
		"apprenticeLiquefiedOxybenzene#foDth/e4qEuDMA1UspMlolAIxSoEN20xF433FF",
		"itsSubstantiveDeafAndDumbPerson#38S9/zpJ77bnc3jQnxwfsi8ouVF/St0xFBB117",
		"aParticularFeudalisticGemma#DBBH33YolG+cJGN44VGw2qSM8M/7s80x893BFF",
		"mcHeterologicPensacola#MH5UXonBleimbDRmDyXGfDArXdOJQk0xE9AB17",
		"recruitBillowyIntestine#g8AmNtoK4/ympAKDGqdtOmPJ0JW/PR0xC58917",
		"rookieRhetoricalMorocco#5xrdkIFsHGxYApAvWKcXRZg2KN06jX0x87F717",
		"padreScrubbyFelloe#GS3iJ2W6bs7VnnKOQwa2o2iTgGqTAi0x59E817",
		"aFramedTrypsinogen#/usy7acxjOL2kPx7JJLFZe9HtTC5Sr0xF6358A",
		"yourRightEyedMindset#nLDg1OX2lbDIE7/0G+S8AZxUsvYsME0x8AFB17",
		"deputyIndoGermanicBaltoSlavonic#0Z0odw3VMwPGO38jLhSu719UTpIpIq0x8BB381",
		"rookieNonpersonalWeighingMachine#PJ/HxMkKXOlxwbnJXcWy/uE+1BfIcI0xE77471",
		"hisReversiveAceOfSpades#kuMUS/CM7x6Kmug2ZhSA7kq7xkC42W0xC9BE62",
		"sergeantHowlingOpenWeave#Dj1d5Jr6U/dm5F3p1BThm0eRtOrsgK0xFAAFBA",
		"padreMostValuableWordPainting#xgvcUcqQxezQPNi5vAYE1a/c+H3MAo0xC12283",
		"myMeanspiritedCarobPowder#XbYzYUhlZTHeSNEhzueijbQXX7HpQO0xE18B6B",
	}
	for i := 0; i < numtests; i++ {
		id, _ := GenerateIdentity(rng)
		codenames = append(codenames, id.Codename+"#"+id.Extension+
			id.Color)
	}

	for i := 0; i < numtests; i++ {
		if codenames[i] != expectedCodeNames[i] {
			t.Errorf("Codename %d do not match - %s vs %s", i, codenames[i], expectedCodeNames[i])
		}
	}

	logstr := "codenames := []string {"
	for i := 0; i < numtests; i++ {
		logstr = fmt.Sprintf(logstr+"\n\t\"%s\",", codenames[i])
	}
	logstr = fmt.Sprintf(logstr + "\n}")
	t.Logf(logstr)
}

// Checks that PrivateIdentity.Marshal and UnmarshalPrivateIdentity are inverse
// operations.
func TestPrivateIdentity_MarshalUnmarshal(t *testing.T) {

	rng := &csprng.SystemRNG{}
	privateIdentity, _ := GenerateIdentity(rng)
	marshalledData := privateIdentity.Marshal()

	receivedIdentity, err := UnmarshalPrivateIdentity(marshalledData)
	if err != nil {
		t.Fatalf("UnmarshalPrivateIdentity error: %+v", err)
	}

	if !reflect.DeepEqual(receivedIdentity, privateIdentity) {
		t.Fatalf("UnmarshalPrivateIdentity did not construct identical "+
			"identity from original structure."+
			"\nExpected: %v"+
			"\nReceived: %v", privateIdentity, receivedIdentity)
	}

}

// Checks that Identity.Marshal and UnmarshalIdentity are inverse
// operations.
func TestIdentity_MarshalUnmarshal(t *testing.T) {

	rng := &csprng.SystemRNG{}
	privateIdentity, _ := GenerateIdentity(rng)
	expected := privateIdentity.Identity
	marshalledData := expected.Marshal()

	received, err := UnmarshalIdentity(marshalledData)
	if err != nil {
		t.Fatalf("UnmarshalIdentity error: %+v", err)
	}

	if !reflect.DeepEqual(expected, received) {
		t.Fatalf("UnmarshalIdentity did not construct identical identity "+
			"from orignal structure."+
			"\nExpected: %v"+
			"\nReceived: %v", expected, received)
	}

}

// Error case: UnmarshalPrivateIdentity should error when receiving
// byte data that is not of length
// [ed25519.PrivateKeySize] + [ed25519.PublicKeySize] + 1.
func TestUnmarshalPrivateIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalPrivateIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalPrivateIdentity should error when receiving byte data " +
			"that is too short.")
	}
}

// Error case: UnmarshalIdentity should error when receiving
// byte data that is not of length [ed25519.PublicKeySize] + 1.
func TestUnmarshalIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalIdentity should error when receiving byte data " +
			"that is too short.")
	}
}
