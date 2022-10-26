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
		"mrPleochroicBurmannia#CJBQ1Z7JR7B92gVvitmJbuzyQLOIHm0x77BFC7",
		"theirScorbuticGovernmentOfficials#diTJfbO4VEdjfsRZ78Lw46mG5B4s3Y0x57FEFF",
		"itsForkLikeLick#eyrYJ5rkz2S0geIaKRxlhVtMd1lzvg0x57FEFF",
		"brotherGrenadianMonocarp#IGXyptJWwIEvodXOQelrok5/I+d6Wv0xFFE87C",
		"meistroShiftingPachytene#JHfoarwsvjQMY5iZypfxQPBoa+US3T0xFDEEF4",
		"masterMindedStubble#J7sDlY7bHn8Iu3XPte6pga5ZaWLfT20xF6358A",
		"myTherapeuticalAlert#y8mnzmlzQVUMPgMByUtpV1X8HNdp/m0x56A5EC",
		"hisImbricateGeneral#0OQddD1SY9IOyfoFDtGXquChG/kCXt0xE18B6B",
		"myScentlessWindshield#VQB+elebg54sG1o9AyzDiSDIGKo6S70xB041FF",
		"noviceRecessionarySoundReflection#u0P0nkNbHDMHi12fwtSISDW3wxEBDs0xC5908E",
		"thisOverseasPanhysterectomy#iIvJy9nuiJg7H3TLwumyN37vtTrdr60xE238EC",
		"aCerebrovascularNephritis#WtAoXbvG/Dhts/hODSvH6hDclfN33E0x57E964",
		"mrUnoffendingRood#aqhA8UEV525NUucnkHQdfymVDAL2xb0xFAAFBE",
		"apprenticeQuickFrozenPycnogonida#FIzpM5LrItNjLFZpIiMhV0rx6kqoLM0xC9BE62",
		"ladyCrustaceousJosephBlack#+0kY0+W/mN9Vk8fOk536zGFu5JVi6K0xF88017",
		"electorTransformableDeceiver#7/U4P2FKBAaHX7CquQ3oQac1++aBY+0xB041FF",
		"aConicJohnDewey#G6omqBoKDTL4NFpic5P+IpuKkfbbeY0xA74AC7",
		"msUnqualifiedModification#du1ojRiL7pU4Owq4o1cjK7qzYBX5tR0x4CC417",
		"ourMotivativeWatershed#7IspUGfv8lFjf3j9pxI9aN2xiiQGE40x48CCCD",
		"hisUntemperedTwelvemonth#XVECxCH7ZPU5qCsyLgnnDwmUWsT4P00xE9AB17",
		"aCertainVexedQuarryman#oTPqAD4ZVfSI9u+6NnA2HBDwmoMiq20xCA226B",
		"jrValidatedEroding#CBhMFc2S4EsMaOF361VVjJugepEEbU0xF75D59",
		"djAuditoryPicketFence#UyJJFRRYjaOjJ78pQ5nMV9wxKGCSqN0xE41B17",
		"coachUnbefittingPhyllostachys#Fx+XJnd3aongZqcaXJtAFyUYUTlYpD0xFFFC17",
		"mayorAlertPinkness#8VDrAkNQomebVKsa+BRR7+QOUtFcS10xECD672",
		"privateOutlyingBamboo#ON7m/yKsp8nIWK3XnrT5+x+Lcv8MnP0xC7A317",
		"thisDegenerateSannup#TQDfTRTkRtk17mC66/V5V1h6Lmxtnj0x00FFFF",
		"mrPursuedPleasureCraft#OQIxTFPiDXuH8C5DzlQMZtblOY3v5J0xF6358A",
		"apprenticeAbstentiousBacteriologist#1mYeBOM8W9l155FPtQrS8lO+7P7OVG0xD462FF",
		"thisEyeDeceivingReadability#n7WfNv5sU7k14YwnKvkbSEe1Q+ZbA20xE56E94",
		"recruitValetudinaryReliance#Do33eHXNpszdIg48vxu54NJ6Z/NZLV0x5EFB6E",
		"theirLoweredVacuum#vZZW1mpxAHySKuVVdZg2efSi7agsrA0x43C6DB",
		"hisInhospitableIndelibleInk#bMcXb1srnFLumAEvm8YxFG1TxqO2310x43BFC7",
		"aGloriousNoctuid#aYgewQbqBlL1z+Bvd5S3sCLPptCck70xA0C544",
		"baronessNiloticStonehenge#YZN14FDNGhfrvglD2fbF4h1Wjtn9LW0x48CCCD",
		"thatWellFoundedSepiidae#8es/JqPu6qTL6N5VTwD3udCa2X5sGN0x5EFB6E",
		"itsOpenheartedEdentata#8GTh/1guvSfcHdg7u6+2Z6kCKHQqgD0xFFF8C6",
		"yourAloofEmbrace#gKckIJS6r+Fr5KJ7UmP+cnCgENCxVR0x57FEFF",
		"msUntaggedPurge#jKXmp0xHki2DDaYGuzrJxT3Buyw0r30xC6AEC7",
		"thisRhapsodicAcrostic#9iW47PUFZobB40jLa/Ircd15R9UOX40xF665AB",
		"meistroPrecariousAshtoreth#AiHgclVykhE117QZLUsLDe3PyaiL//0xF75D59",
		"apprenticeWellTriedGayal#kOAubHhdI4YSiddHZtiaxVz5L30VQs0xE41B17",
		"myPermutableLablab#jLoLArQEWCO0mijjlszerWYgUAp0c20xF6358A",
		"myUnstoppableMsec#/Ly7aeiOzDfxarK0JdB5ub/o5SJ9J+0x43BFC7",
		"seniorScandalousWilfulness#sfuEVKCLqg0ZU2e9dpk+TowWfxDnrU0x7FE817",
		"yourGovernmentalLinebacker#RhkPV4oeDc4MQJj29OdER51O1TBJJe0x52D017",
		"myAnoperinealTough#0SP+BRiIXUhmweMfPFhnbSENP16ZlZ0xE0FFFF",
		"newbieAlbuminuricRhodochrosite#CQosQspA5p6Nmg6iIFX4fveCiZuWis0x9E7BFF",
		"mrPreferentLocustBean#4CNwfPw4hQb5NuPVXwI4aAr8Ams++J0xF6358A",
		"mrBeyondDoubtGourdVine#EP1WyHh21rAmSUT+5aNMoJb4I6/eKb0xCA226B",
		"hisYellowBelliedOverconfidence#nVCP1OkG2Kob462gdeFSGlpHTKNXqM0xC12283",
		"thatMordantPicnic#s5CDyaJCyflp94Nht60BgMynfQIxt60x64E986",
		"uncleXerographicGuardianship#oSpGyMiORey7lqbIAcgL2H5MTWs87n0x00FFFF",
		"recruitUnretentiveCheeseboard#/PTDWmUsAOIYm5OjO+i68maTs5ZQ320x43BFC7",
		"aGlutinousDivination#Ey44JvrTjZc5bw1THQ/FCjQDboixk70xEDE275",
		"fledgelingOuterHelicopter#CFBonykLjYHMzGESusgET+ojZXnXy+0x3EA99F",
		"intracellularMartini#of1pNqREHIQeNV/qjtclGr1K3EZAOE0xEDDA74",
		"freshiePasseReticle#xEn2zV0WoZowqE/anGrXEkXclKDEjm0x48CCCD",
		"sergeantSmallGrainedPlatform#6eNDFseaT07bWJ7XbhxUi4hadmGWkO0x3EA99F",
		"senoraFundedFalseBelief#nD+VIRKJFpOVjm8jnTjLXLwkWNVHoJ0xC68E17",
		"senorQuintessentialDisciplesOfChrist#UcEhk455MmNyx8aZv/ninLoGk+t9+H0xC48793",
		"jrCalcicolousStaff#9ONAWOcBCb32QvAq2XAZRjt82iA7us0xC25A7C",
		"mcBlightedFiligree#D6DvIW4Ett7mAm9yPrqzudLYCiVqCQ0xC12267",
		"madameUnreactiveAnxiolytic#6f+VMw9K669bzC7+Yhg+WzEg8UZWnW0xB38481",
		"herObliqueBestFriend#dC3bCc9Pnum6PJ6FZbxAdaqgK/OgDa0xE18B6B",
		"inspectorMunificentMottle#t3GIfdsaml800cqHQovmhY6CapFW9V0x54C571",
		"theirClearYhvh#CxgaD4atGCC2ySR1FUjbuVNEgy5aBP0x57FEFF",
		"mcArchingParameter#AosH51cvf16D7e+ngycHz1qMafxaED0xF75D59",
		"oneLetteredRailwayLine#R3nMp5DTaVJ7lM7AivOpMQGfEedlPA0xB38481",
		"senorShamMycelium#MgfelOEBdci1MYxvCFVg+GOmXYesRv0xE7A1B0",
		"adeptRelativeReenforcement#xET81e2mef+GNsepulMKS4qHzVNXg80x8AFB17",
		"herOutfittedAldol#cazZBzanh8y0/pH5oFsKX3kggDYUhC0x00FFFF",
		"oneBriaryUsufruct#nEax3bLPHQnUGeKB0XAKAZWKbIXrMY0x1589FF",
		"mrMultipotentMentum#VUW+i98apTF35NvwGp1jsgK1dh/pHr0xE3319D",
		"itsSandySmash#xm7wVal361xYnPfeQgB7LT890VRObk0xC6DEFF",
		"msUnmeritoriousHenryMiller#11ohNjlcsuclZAfIUIt84U4JwCwU2b0xFFFF00",
		"herrNimbleTulip#GVptxNdWnI5ExW1xizO/AojF17oD/90xE6A9EC",
		"senoritaWhackedParaphysis#LUVWIV8khBXd6nZRPRaQuiHO5g0XOs0x1589FF",
		"tioCeremoniousMattock#9Qv4vcwkBAvj6x6qOUyYfPP0nFKKv/0xFF0000",
		"theirProjectingDuette#DPL5HrXuemKD4fTUIyxGBUBFrP4L5f0xC12267",
		"mayorTwentySixRush#04XTUr4bdtfuXRlgvqHaydSoI8jrvB0x488AC7",
		"hisAntipatheticalFinancialLoss#gx3HpBXMc7pk/B1ClkJqORpl7mxjs10xF75D59",
		"hisFanaticCeaseAndDesistOrder#oxWVz57MNz1JG/JgzNusw0fAdHiq0D0xFAAFBA",
		"jrComfortingPrate#4tBa2MKTV3W6+Pgr7wuNd6GxtvQ3r/0x82CAFA",
		"juniorPodlikeListon#rC+WyvBvP1z2chh4caISyKtrAwGnk40xD462FF",
		"thatSceptredPepperoni#foDth/e4qEuDMA1UspMlolAIxSoEN20xF433FF",
		"apprenticeWoolyMindedChlorenchyma#38S9/zpJ77bnc3jQnxwfsi8ouVF/St0xFBB117",
		"thatUnthankfulHeraldry#DBBH33YolG+cJGN44VGw2qSM8M/7s80x893BFF",
		"corporalVerbalDelinquent#MH5UXonBleimbDRmDyXGfDArXdOJQk0xE9AB17",
		"lordAmokOpenLetter#g8AmNtoK4/ympAKDGqdtOmPJ0JW/PR0xC58917",
		"myUnstagedAttrition#5xrdkIFsHGxYApAvWKcXRZg2KN06jX0x87F717",
		"theAftermostFencingMaterial#GS3iJ2W6bs7VnnKOQwa2o2iTgGqTAi0x59E817",
		"recruitPracticalChrysalis#/usy7acxjOL2kPx7JJLFZe9HtTC5Sr0xF6358A",
		"representativeOldenOligarch#nLDg1OX2lbDIE7/0G+S8AZxUsvYsME0x8AFB17",
		"wardenUncomparableCraft#0Z0odw3VMwPGO38jLhSu719UTpIpIq0x8BB381",
		"juniorArborousRobin#PJ/HxMkKXOlxwbnJXcWy/uE+1BfIcI0xE77471",
		"senorCeilingedLeaveOfAbsence#kuMUS/CM7x6Kmug2ZhSA7kq7xkC42W0xC9BE62",
		"rookieUnanticipatedAbiesVenusta#Dj1d5Jr6U/dm5F3p1BThm0eRtOrsgK0xFAAFBA",
		"mcExegeticalDisparagement#xgvcUcqQxezQPNi5vAYE1a/c+H3MAo0xC12283",
		"hisCasuisticalSaccharase#XbYzYUhlZTHeSNEhzueijbQXX7HpQO0xE18B6B",
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
