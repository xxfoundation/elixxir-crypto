////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package codename

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
)

func TestConstructIdentity(t *testing.T) {
	const numTests = 100
	rng := &csprng.SystemRNG{}
	codenames := make([]string, numTests)

	for i := range codenames {
		id, _ := GenerateIdentity(rng)
		codenames[i] = id.Codename + "#" + id.Extension + id.Color
	}

	for i := 0; i < numTests; i++ {
		for j := i + 1; j < numTests; j++ {
			if codenames[i] == codenames[j] {
				t.Errorf("Codenames %d and %d are the same."+
					"\ncodename %d: %s\ncodename %d: %s",
					i, j, i, codenames[i], j, codenames[j])
			}
		}
	}
}

func TestConstructIdentity_Vector(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	expectedCodenames := []string{
		"aWellKnownDownScoopShovel#CJBQ1Z7JR7B92gVvitmJbuzyQLOIHm0x77BFC7",
		"mrDisruptiveFullback#diTJfbO4VEdjfsRZ78Lw46mG5B4s3Y0x57FEFF",
		"juniorNeriticRicer#eyrYJ5rkz2S0geIaKRxlhVtMd1lzvg0x57FEFF",
		"freshieUndueUntidiness#IGXyptJWwIEvodXOQelrok5/I+d6Wv0xFFE87C",
		"tiaCorkedBasis#JHfoarwsvjQMY5iZypfxQPBoa+US3T0xFDEEF4",
		"thisPeltateJudicialPrinciple#J7sDlY7bHn8Iu3XPte6pga5ZaWLfT20xF6358A",
		"theObligationalNovocain#y8mnzmlzQVUMPgMByUtpV1X8HNdp/m0x56A5EC",
		"juniorUndoableCapsicum#0OQddD1SY9IOyfoFDtGXquChG/kCXt0xE18B6B",
		"ourUnwoundedRoyalAcademyOfArts#VQB+elebg54sG1o9AyzDiSDIGKo6S70xB041FF",
		"señorGrilledConfect#u0P0nkNbHDMHi12fwtSISDW3wxEBDs0xC5908E",
		"brotherLonghandConvalescence#iIvJy9nuiJg7H3TLwumyN37vtTrdr60xE238EC",
		"sisterBasidialRosaceae#WtAoXbvG/Dhts/hODSvH6hDclfN33E0x57E964",
		"mayorHoraryMiddle#aqhA8UEV525NUucnkHQdfymVDAL2xb0xFAAFBE",
		"señorMulticellularSpecs#FIzpM5LrItNjLFZpIiMhV0rx6kqoLM0xC9BE62",
		"coachFoggedContourLine#+0kY0+W/mN9Vk8fOk536zGFu5JVi6K0xF88017",
		"coachReformistSeneschal#7/U4P2FKBAaHX7CquQ3oQac1++aBY+0xB041FF",
		"thisVotelessDeviceCharacteristic#G6omqBoKDTL4NFpic5P+IpuKkfbbeY0xA74AC7",
		"theirDissonantOpticalIllusion#du1ojRiL7pU4Owq4o1cjK7qzYBX5tR0x4CC417",
		"tiaInsectanSilverworker#7IspUGfv8lFjf3j9pxI9aN2xiiQGE40x48CCCD",
		"señoritaFoliateCardiograph#XVECxCH7ZPU5qCsyLgnnDwmUWsT4P00xE9AB17",
		"chiefCutOutAvower#oTPqAD4ZVfSI9u+6NnA2HBDwmoMiq20xCA226B",
		"theirIllAtEaseAuctionPitch#CBhMFc2S4EsMaOF361VVjJugepEEbU0xF75D59",
		"djAstylarHominyGrits#UyJJFRRYjaOjJ78pQ5nMV9wxKGCSqN0xE41B17",
		"rookieLxivIodoaminoAcid#Fx+XJnd3aongZqcaXJtAFyUYUTlYpD0xFFFC17",
		"coachUnpractisedArbutus#8VDrAkNQomebVKsa+BRR7+QOUtFcS10xECD672",
		"itsPyrogenicImpendence#ON7m/yKsp8nIWK3XnrT5+x+Lcv8MnP0xC7A317",
		"msUnsurprisingGorger#TQDfTRTkRtk17mC66/V5V1h6Lmxtnj0x00FFFF",
		"thisDemographicBackfire#OQIxTFPiDXuH8C5DzlQMZtblOY3v5J0xF6358A",
		"theSagittateJudaism#1mYeBOM8W9l155FPtQrS8lO+7P7OVG0xD462FF",
		"yourIncreasedUpthrow#n7WfNv5sU7k14YwnKvkbSEe1Q+ZbA20xE56E94",
		"theHarmoniousEthmoid#Do33eHXNpszdIg48vxu54NJ6Z/NZLV0x5EFB6E",
		"monsieurUnconfirmedTablature#vZZW1mpxAHySKuVVdZg2efSi7agsrA0x43C6DB",
		"señoraNecklikeElastic#bMcXb1srnFLumAEvm8YxFG1TxqO2310x43BFC7",
		"representativeAniseikonicDuct#aYgewQbqBlL1z+Bvd5S3sCLPptCck70xA0C544",
		"señorClarifyingSepal#YZN14FDNGhfrvglD2fbF4h1Wjtn9LW0x48CCCD",
		"djEntertainedAnagoge#8es/JqPu6qTL6N5VTwD3udCa2X5sGN0x5EFB6E",
		"apprenticeDepartedBoringness#8GTh/1guvSfcHdg7u6+2Z6kCKHQqgD0xFFF8C6",
		"noviceUntaggedGoodForm#gKckIJS6r+Fr5KJ7UmP+cnCgENCxVR0x57FEFF",
		"adeptDualSunberry#jKXmp0xHki2DDaYGuzrJxT3Buyw0r30xC6AEC7",
		"myGarrulousDeception#9iW47PUFZobB40jLa/Ircd15R9UOX40xF665AB",
		"fledgelingPolycrystallineIngot#AiHgclVykhE117QZLUsLDe3PyaiL//0xF75D59",
		"myObsessiveHueAndCry#kOAubHhdI4YSiddHZtiaxVz5L30VQs0xE41B17",
		"mcEvidentiaryVolgaic#jLoLArQEWCO0mijjlszerWYgUAp0c20xF6358A",
		"jrMercerizedBowlingEquipment#/Ly7aeiOzDfxarK0JdB5ub/o5SJ9J+0x43BFC7",
		"rookieToughenedNewMexico#sfuEVKCLqg0ZU2e9dpk+TowWfxDnrU0x7FE817",
		"aWellKnownPurpleRedTulipPoplar#RhkPV4oeDc4MQJj29OdER51O1TBJJe0x52D017",
		"inspectorFileLikeDeaminization#0SP+BRiIXUhmweMfPFhnbSENP16ZlZ0xE0FFFF",
		"juniorBrisantOvercharge#CQosQspA5p6Nmg6iIFX4fveCiZuWis0x9E7BFF",
		"myUnspecialisedHydrocharidaceae#4CNwfPw4hQb5NuPVXwI4aAr8Ams++J0xF6358A",
		"deputyDuplicatableConferrer#EP1WyHh21rAmSUT+5aNMoJb4I6/eKb0xCA226B",
		"mcPaleocorticalAmericanDream#nVCP1OkG2Kob462gdeFSGlpHTKNXqM0xC12283",
		"thatSausageShapedImmortelle#s5CDyaJCyflp94Nht60BgMynfQIxt60x64E986",
		"itsAstonishedMalePlug#oSpGyMiORey7lqbIAcgL2H5MTWs87n0x00FFFF",
		"councillorPillaredAntiviralAgent#/PTDWmUsAOIYm5OjO+i68maTs5ZQ320x43BFC7",
		"jrSilveryGreyIndene#Ey44JvrTjZc5bw1THQ/FCjQDboixk70xEDE275",
		"broadbandTaxation#CFBonykLjYHMzGESusgET+ojZXnXy+0x3EA99F",
		"sergeantExpectantLowGear#of1pNqREHIQeNV/qjtclGr1K3EZAOE0xEDDA74",
		"directorCompatibleFlutter#xEn2zV0WoZowqE/anGrXEkXclKDEjm0x48CCCD",
		"mrCreepyMultiplex#6eNDFseaT07bWJ7XbhxUi4hadmGWkO0x3EA99F",
		"corporalApostrophicGoat#nD+VIRKJFpOVjm8jnTjLXLwkWNVHoJ0xC68E17",
		"señorSpinousMorphea#UcEhk455MmNyx8aZv/ninLoGk+t9+H0xC48793",
		"thisManyAnotherArrears#9ONAWOcBCb32QvAq2XAZRjt82iA7us0xC25A7C",
		"seniorUnappetisingRawWool#D6DvIW4Ett7mAm9yPrqzudLYCiVqCQ0xC12267",
		"jrPoundFoolishStephanion#6f+VMw9K669bzC7+Yhg+WzEg8UZWnW0xB38481",
		"deputyArcticGraduatingClass#dC3bCc9Pnum6PJ6FZbxAdaqgK/OgDa0xE18B6B",
		"mrRopeyTheHalt#t3GIfdsaml800cqHQovmhY6CapFW9V0x54C571",
		"drOpprobriousResult#CxgaD4atGCC2ySR1FUjbuVNEgy5aBP0x57FEFF",
		"chiefMiddleFoodFish#AosH51cvf16D7e+ngycHz1qMafxaED0xF75D59",
		"itsOtherPhotometer#R3nMp5DTaVJ7lM7AivOpMQGfEedlPA0xB38481",
		"oldmanDefendableComprehensive#MgfelOEBdci1MYxvCFVg+GOmXYesRv0xE7A1B0",
		"aWellKnownEnoughOpticalFiber#xET81e2mef+GNsepulMKS4qHzVNXg80x8AFB17",
		"ladyJocundSidalcea#cazZBzanh8y0/pH5oFsKX3kggDYUhC0x00FFFF",
		"mcSurroundedSemimonthly#nEax3bLPHQnUGeKB0XAKAZWKbIXrMY0x1589FF",
		"deputyAnalogLobbyist#VUW+i98apTF35NvwGp1jsgK1dh/pHr0xE3319D",
		"aWellKnownPapalNonobservance#xm7wVal361xYnPfeQgB7LT890VRObk0xC6DEFF",
		"sisterMousyUnderdevelopment#11ohNjlcsuclZAfIUIt84U4JwCwU2b0xFFFF00",
		"juniorWoollenLiveliness#GVptxNdWnI5ExW1xizO/AojF17oD/90xE6A9EC",
		"itsUnrecognizedArmiger#LUVWIV8khBXd6nZRPRaQuiHO5g0XOs0x1589FF",
		"monsieurKindlyAccountant#9Qv4vcwkBAvj6x6qOUyYfPP0nFKKv/0xFF0000",
		"señoritaHygienicalImago#DPL5HrXuemKD4fTUIyxGBUBFrP4L5f0xC12267",
		"inspectorBrisantPerchloromethane#04XTUr4bdtfuXRlgvqHaydSoI8jrvB0x488AC7",
		"myLadylikeBitthead#gx3HpBXMc7pk/B1ClkJqORpl7mxjs10xF75D59",
		"constableGrownupBabble#oxWVz57MNz1JG/JgzNusw0fAdHiq0D0xFAAFBA",
		"theirPurposelessForelock#4tBa2MKTV3W6+Pgr7wuNd6GxtvQ3r/0x82CAFA",
		"msAmusiveBandleader#rC+WyvBvP1z2chh4caISyKtrAwGnk40xD462FF",
		"sisterLiquefiedProgestogen#foDth/e4qEuDMA1UspMlolAIxSoEN20xF433FF",
		"srSubstantiveElectromagnetics#38S9/zpJ77bnc3jQnxwfsi8ouVF/St0xFBB117",
		"yourFeudalisticHorizontal#DBBH33YolG+cJGN44VGw2qSM8M/7s80x893BFF",
		"lordHeterologicRadiationPattern#MH5UXonBleimbDRmDyXGfDArXdOJQk0xE9AB17",
		"fledgelingBillowyLyrist#g8AmNtoK4/ympAKDGqdtOmPJ0JW/PR0xC58917",
		"freshieRhetoricalPatrimony#5xrdkIFsHGxYApAvWKcXRZg2KN06jX0x87F717",
		"señoritaScrubbyGoogol#GS3iJ2W6bs7VnnKOQwa2o2iTgGqTAi0x59E817",
		"aFramedPall#/usy7acxjOL2kPx7JJLFZe9HtTC5Sr0xF6358A",
		"inRightEyedPaleography#nLDg1OX2lbDIE7/0G+S8AZxUsvYsME0x8AFB17",
		"freshieIndoGermanicBurr#0Z0odw3VMwPGO38jLhSu719UTpIpIq0x8BB381",
		"freshieNonpersonalTrouper#PJ/HxMkKXOlxwbnJXcWy/uE+1BfIcI0xE77471",
		"itsReversiveArrestedDevelopment#kuMUS/CM7x6Kmug2ZhSA7kq7xkC42W0xC9BE62",
		"mistressHowlingPosting#Dj1d5Jr6U/dm5F3p1BThm0eRtOrsgK0xFAAFBA",
		"señoritaMostValuableRededication#xgvcUcqQxezQPNi5vAYE1a/c+H3MAo0xC12283",
		"djMeanspiritedComplacency#XbYzYUhlZTHeSNEhzueijbQXX7HpQO0xE18B6B",
	}
	codenames := make([]string, len(expectedCodenames))

	for i := range codenames {
		id, _ := GenerateIdentity(rng)
		codenames[i] = id.Codename + "#" + id.Extension + id.Color
	}

	for i, expected := range expectedCodenames {
		if codenames[i] != expected {
			t.Errorf("Codename %d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, codenames[i], expected)
		}
	}

	var logStr string
	for _, codename := range codenames {
		logStr = fmt.Sprintf(logStr+"\n\t\"%s\",", codename)
	}
	t.Logf("codenames := []string {" + logStr + "\n}")
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
			"identity from original structure.\nexpected: %v\nreceived: %v",
			privateIdentity, receivedIdentity)
	}
}

// Checks that Identity.Marshal and UnmarshalIdentity are inverse operations.
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
			"from orignal structure.\nexpected: %v\nreceived: %v",
			expected, received)
	}
}

// Error case: UnmarshalPrivateIdentity should error when receiving byte data
// that is not of length [ed25519.PrivateKeySize] + [ed25519.PublicKeySize] + 1.
func TestUnmarshalPrivateIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalPrivateIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalPrivateIdentity should error when receiving byte data " +
			"that is too short.")
	}
}

// Error case: UnmarshalIdentity should error when receiving byte data that is
// not of length [ed25519.PublicKeySize] + 1.
func TestUnmarshalIdentity_Error(t *testing.T) {
	empty := []byte("too short")
	_, err := UnmarshalIdentity(empty)
	if err == nil {
		t.Fatalf("Expected error case was not met. " +
			"UnmarshalIdentity should error when receiving byte data " +
			"that is too short.")
	}
}
