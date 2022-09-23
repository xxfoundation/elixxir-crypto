////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"gitlab.com/xx_network/crypto/csprng"
	"math/rand"
	"reflect"
	"testing"
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
	expectedCodeNames := []string{"thisPatheticCheck-In#CJBQ1Z7JR7B92gVvitmJbuzyQLOIHm0xBABD23", "excellencyRevertibleHinault#diTJfbO4VEdjfsRZ78Lw46mG5B4s3Y0x5ACB3F", "majorFilledMalfunction#eyrYJ5rkz2S0geIaKRxlhVtMd1lzvg0xEBFFE5", "corporalWarm-TonedNebcin#IGXyptJWwIEvodXOQelrok5/I+d6Wv0xF3F8F3", "mySavedPatriotism#JHfoarwsvjQMY5iZypfxQPBoa+US3T0x0EFCF0", "thisMagisterialSuzerain#J7sDlY7bHn8Iu3XPte6pga5ZaWLfT20xFEFCFC", "privateStypticAberdare#y8mnzmlzQVUMPgMByUtpV1X8HNdp/m0xE570FE", "privateHomeAfrl#0OQddD1SY9IOyfoFDtGXquChG/kCXt0xECD9F2", "generalRetroflexedWulfila#VQB+elebg54sG1o9AyzDiSDIGKo6S70x4F6CE0", "thisPronounceableSquatting#u0P0nkNbHDMHi12fwtSISDW3wxEBDs0xEFFEFE", "myObservablePelecaniformes#iIvJy9nuiJg7H3TLwumyN37vtTrdr60x6933DF", "lieutenantCata-CorneredObscenity#WtAoXbvG/Dhts/hODSvH6hDclfN33E0xEAFCDE", "thisUncorrelatedSandhi#aqhA8UEV525NUucnkHQdfymVDAL2xb0xE9E9FF", "privatePreponderantRappahannock#FIzpM5LrItNjLFZpIiMhV0rx6kqoLM0xFAF8F0", "thatCounterproductiveLent#+0kY0+W/mN9Vk8fOk536zGFu5JVi6K0xFBECFF", "mySyncreticalDriver#7/U4P2FKBAaHX7CquQ3oQac1++aBY+0xEFF7FA", "drCommonLeech#G6omqBoKDTL4NFpic5P+IpuKkfbbeY0x307BAE", "thatUndiscerningNard#du1ojRiL7pU4Owq4o1cjK7qzYBX5tR0xFF8619", "sergeantMediocreWhite#7IspUGfv8lFjf3j9pxI9aN2xiiQGE40x41CE18", "privateUninjuredUnesco#XVECxCH7ZPU5qCsyLgnnDwmUWsT4P00x3F949C", "unremittingReactance#oTPqAD4ZVfSI9u+6NnA2HBDwmoMiq20x860C86", "thisUnpersuadableFlowerbed#CBhMFc2S4EsMaOF361VVjJugepEEbU0xE7F2F9", "myAtrophiedPlo#UyJJFRRYjaOjJ78pQ5nMV9wxKGCSqN0xE6F1EE", "theWizardlyPlaying#Fx+XJnd3aongZqcaXJtAFyUYUTlYpD0xF5E4F5", "sirAlbuminuricPolaris#8VDrAkNQomebVKsa+BRR7+QOUtFcS10xE0FEE8", "ourNorthmostBreadbasket#ON7m/yKsp8nIWK3XnrT5+x+Lcv8MnP0xFFD8D8", "damningScrutiniser#TQDfTRTkRtk17mC66/V5V1h6Lmxtnj0xF6EBE6", "thisPrayerfulPoser#OQIxTFPiDXuH8C5DzlQMZtblOY3v5J0xBA70FE", "admiralAbstractBrachinus#1mYeBOM8W9l155FPtQrS8lO+7P7OVG0x3B4ECA", "thisEtiologicalReport#n7WfNv5sU7k14YwnKvkbSEe1Q+ZbA20x6379FF", "drUnpermedRidgepole#Do33eHXNpszdIg48vxu54NJ6Z/NZLV0xEBFFE5", "privateLawfulVeranda#vZZW1mpxAHySKuVVdZg2efSi7agsrA0x4CD60C", "corporalImplementalKatabolism#bMcXb1srnFLumAEvm8YxFG1TxqO2310xAEB018", "drFugalOne-Ninth#aYgewQbqBlL1z+Bvd5S3sCLPptCck70xC03B60", "regentMoneylessSunburst#YZN14FDNGhfrvglD2fbF4h1Wjtn9LW0x41CE18", "directorUnthreateningShowing#8es/JqPu6qTL6N5VTwD3udCa2X5sGN0xFDFAEB", "colonelNonmonotonicEzed#8GTh/1guvSfcHdg7u6+2Z6kCKHQqgD0xF3FBF2", "myAllopatricFerule#gKckIJS6r+Fr5KJ7UmP+cnCgENCxVR0x5ACB3F", "thatUnindustrialisedRamman#jKXmp0xHki2DDaYGuzrJxT3Buyw0r30xFFEDDD", "thatRacketyArdor#9iW47PUFZobB40jLa/Ircd15R9UOX40xE4E0FA", "myPhantomBlastopore#AiHgclVykhE117QZLUsLDe3PyaiL//0xE7F2F9", "sergeantUntrodHandicapper#kOAubHhdI4YSiddHZtiaxVz5L30VQs0xDAE2F9", "sirOverheatedLoewi#jLoLArQEWCO0mijjlszerWYgUAp0c20xFCF4DE", "privateXenogeneicNewsprint#/Ly7aeiOzDfxarK0JdB5ub/o5SJ9J+0xAEB018", "retainedWoolworth#sfuEVKCLqg0ZU2e9dpk+TowWfxDnrU0xD05353", "gentlemanGaelic-SpeakingManitoba#RhkPV4oeDc4MQJj29OdER51O1TBJJe0xE1BA5E", "thatAnkle-DeepAnogramma#0SP+BRiIXUhmweMfPFhnbSENP16ZlZ0x0DF447", "myAlaryRun#CQosQspA5p6Nmg6iIFX4fveCiZuWis0xFF6CD0", "thisPhotosyntheticMash#4CNwfPw4hQb5NuPVXwI4aAr8Ams++J0xF0F8E1", "thisBellicoseHijaz#EP1WyHh21rAmSUT+5aNMoJb4I6/eKb0x860C86", "regentVerbatimParting#nVCP1OkG2Kob462gdeFSGlpHTKNXqM0xF9F1ED", "privateMeagerlyPlotter#s5CDyaJCyflp94Nht60BgMynfQIxt60xFFF6E4", "ourVelvety-FurredHospitalization#oSpGyMiORey7lqbIAcgL2H5MTWs87n0xF7F7E4", "sirUnequivocalContester#/PTDWmUsAOIYm5OjO+i68maTs5ZQ320xAEB018", "lordFull-CladEoraptor#Ey44JvrTjZc5bw1THQ/FCjQDboixk70x822B98", "north-polarImmunogenicity#CFBonykLjYHMzGESusgET+ojZXnXy+0xD6B20C", "thisIndisposedMintage#of1pNqREHIQeNV/qjtclGr1K3EZAOE0x4416B1", "gentlemanOpponentRostrum#xEn2zV0WoZowqE/anGrXEkXclKDEjm0xF6EBE6", "thisSemiconsciousPorcellionidae#6eNDFseaT07bWJ7XbhxUi4hadmGWkO0xEFF7FA", "thatForbiddingFund#nD+VIRKJFpOVjm8jnTjLXLwkWNVHoJ0xFCFAEB", "myXxxviiEncomium#UcEhk455MmNyx8aZv/ninLoGk+t9+H0xF6EDE2", "thisBulletproofStrangulation#9ONAWOcBCb32QvAq2XAZRjt82iA7us0xF5E4F5", "myBisteredGeneticist#D6DvIW4Ett7mAm9yPrqzudLYCiVqCQ0x8D2EAE", "thatUndistinguishableAbrasion#6f+VMw9K669bzC7+Yhg+WzEg8UZWnW0xE4FFFD", "lordNewslessCaboodle#dC3bCc9Pnum6PJ6FZbxAdaqgK/OgDa0xECD9F2", "myMetacarpalNeurohypophysis#t3GIfdsaml800cqHQovmhY6CapFW9V0xC6AE57", "masterChocolate-ColoredShahn#CxgaD4atGCC2ySR1FUjbuVNEgy5aBP0x5ACB3F", "privateArbitraryPentimento#AosH51cvf16D7e+ngycHz1qMafxaED0xE7F2F9", "privateJewish-OrthodoxReformer#R3nMp5DTaVJ7lM7AivOpMQGfEedlPA0xE4FFFD", "generalSapphicNon-Involvement#MgfelOEBdci1MYxvCFVg+GOmXYesRv0xFCF0F2", "gentlemanPunctualReynolds#xET81e2mef+GNsepulMKS4qHzVNXg80xF5E4F5", "wardenNortheastAubergine#cazZBzanh8y0/pH5oFsKX3kggDYUhC0x699F6C", "thatBoulderedVendetta#nEax3bLPHQnUGeKB0XAKAZWKbIXrMY0xEFFDE9", "thisMesoblasticMorgan#VUW+i98apTF35NvwGp1jsgK1dh/pHr0xE4EBF8", "myReorganisedAnunnaki#xm7wVal361xYnPfeQgB7LT890VRObk0x0EF5CE", "thatUncommunicativeInanity#11ohNjlcsuclZAfIUIt84U4JwCwU2b0xAD1F7B", "myMongolUltraconservative#GVptxNdWnI5ExW1xizO/AojF17oD/90x6AD2FF", "theUnusedPeoria#LUVWIV8khBXd6nZRPRaQuiHO5g0XOs0xFF5050", "thatCatabolicMixology#9Qv4vcwkBAvj6x6qOUyYfPP0nFKKv/0xD3E4F3", "regentPlenteousEvenness#DPL5HrXuemKD4fTUIyxGBUBFrP4L5f0x8D2EAE", "sirTenuredAmusd#04XTUr4bdtfuXRlgvqHaydSoI8jrvB0xF26FF6", "privateAnticipantGeococcyx#gx3HpBXMc7pk/B1ClkJqORpl7mxjs10xE7F2F9", "privateExceedingColumba#oxWVz57MNz1JG/JgzNusw0fAdHiq0D0xF6EBE6", "thisClxxProtestant#4tBa2MKTV3W6+Pgr7wuNd6GxtvQ3r/0xE1AC0C", "thisPectoralMarantaceae#rC+WyvBvP1z2chh4caISyKtrAwGnk40x3B4ECA", "privateRetrorsePhyllostomidae#foDth/e4qEuDMA1UspMlolAIxSoEN20x9543E7", "corporalUvularCordoba#38S9/zpJ77bnc3jQnxwfsi8ouVF/St0xFFEAF4", "privateUninstructiveIncertitude#DBBH33YolG+cJGN44VGw2qSM8M/7s80x2D87A1", "corporalUnreadAdenanthera#MH5UXonBleimbDRmDyXGfDArXdOJQk0x3F949C", "thatAminicPalaemonidae#g8AmNtoK4/ympAKDGqdtOmPJ0JW/PR0xFFF2FD", "myUngummedBokmal#5xrdkIFsHGxYApAvWKcXRZg2KN06jX0xC78463", "sergeantAfoulGarishness#GS3iJ2W6bs7VnnKOQwa2o2iTgGqTAi0xBC7676", "thatPestiferousCorylaceae#/usy7acxjOL2kPx7JJLFZe9HtTC5Sr0xBA70FE", "myNonagenarianOxydendrum#nLDg1OX2lbDIE7/0G+S8AZxUsvYsME0xEBFCE6", "masterTortiousDibble#0Z0odw3VMwPGO38jLhSu719UTpIpIq0xFF9E45", "thatAproposSalpingitis#PJ/HxMkKXOlxwbnJXcWy/uE+1BfIcI0xEEF4FA", "thisCarmineLyssavirus#kuMUS/CM7x6Kmug2ZhSA7kq7xkC42W0xFCF3F3", "privateThree-FoldAplodontiidae#Dj1d5Jr6U/dm5F3p1BThm0eRtOrsgK0xF1F9FF", "thisEntomophilousEnlightened#xgvcUcqQxezQPNi5vAYE1a/c+H3MAo0x933793", "corporalWrongheadedScanty#XbYzYUhlZTHeSNEhzueijbQXX7HpQO0xECD9F2"}
	for i := 0; i < numtests; i++ {
		id, _ := GenerateIdentity(rng)
		codenames = append(codenames, id.Codename+"#"+id.Extension+
			id.Color)
	}

	for i := 0; i < numtests; i++ {
		if codenames[i]!=expectedCodeNames[i]{
			t.Errorf("Codename %d do not match - %s vs %s", i, codenames[i], expectedCodeNames[i])
		}
	}
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