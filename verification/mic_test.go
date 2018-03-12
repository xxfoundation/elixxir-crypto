package verification

import "testing"

func TestMIC(t *testing.T){

	miclengths := []uint64{26,36,25,25}

	hashdata := make([][][]byte, 4)
	hashdata[0] = make([][]byte, 3)

	hashdata[0][0] = []byte("blarg")
	hashdata[0][1] = []byte("fred")
	hashdata[0][2] = []byte("fredburger")

	hashdata[1] = make([][]byte, 5)

	hashdata[1][0] = []byte("artichoke")
	hashdata[1][1] = []byte("asbestos")
	hashdata[1][2] = []byte("cryptography")
	hashdata[1][2] = []byte("haberdashery")
	hashdata[1][2] = []byte("autometalogolex")

	hashdata[2] = make([][]byte, 1)

	hashdata[2][0] = []byte("arbitrary")

	hashdata[3] = make([][]byte, 9)

	hashdata[3][0] = hashdata[0][0]
	hashdata[3][1] = hashdata[0][1]
	hashdata[3][2] = hashdata[0][2]
	hashdata[3][3] = hashdata[1][0]
	hashdata[3][4] = hashdata[1][1]
	hashdata[3][5] = hashdata[1][2]
	hashdata[3][6] = hashdata[1][3]
	hashdata[3][7] = hashdata[1][4]
	hashdata[3][8] = hashdata[2][0]

	miclist := make([][]byte,len(miclengths))

	for i:=0; i<len(miclist);i++{
		miclist[i] = GenerateMIC(hashdata[i],miclengths[i])
		if uint64(len(miclist[i]))!=miclengths[i]{
			t.Errorf("TestMIC: MIC came back at the wrong size on Index %v" +
				"Expected: %v; Received: %v ", i, miclengths[i], len(miclist))
		}
	}


	for i:=0;i<len(miclist)-1;i++{
		for j:=i+1;j<len(miclist);j++{

			same := true
			for x:=0;x<minlen(miclist[i],miclist[j]);x++{
				if miclist[i][x] != miclist[j][x]{
					same = false
				}
			}

			if same{
				t.Errorf("TestMIC: MICs on index %v and %v are the same",
					i, j)
			}
		}
	}

	for i:=0;i<len(miclist);i++{
		if !CheckMic(hashdata[i],miclist[i]){
			t.Errorf("TestMIC: MICs did not match on inxed %v", i)
		}
	}

	for i:=0;i<len(miclist);i++{
		for j:=i+1;j<len(miclist);j++{
			valid := CheckMic(hashdata[i],miclist[j])
			if valid{
				t.Errorf("TestMIC: Reported valid MIC when invalid with" +
					" index %v and" +
					" %v", i, j)
			}
		}
	}

}

func minlen(a,b []byte) (int){
	if len(a)<len(b){
		return len(a)
	}else{
		return len(b)
	}
}