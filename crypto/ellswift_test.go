package bip324_crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestXSwiftECInv(t *testing.T) {
	testRecords := readCsvFile("xswiftec_inv_test_vectors.csv")
	for _, row := range testRecords[1:] {
		u := getFieldVal(row[0])
		x := getFieldVal(row[1])

		for caseFlag := 0; caseFlag < 8; caseFlag++ {
			t.Run(fmt.Sprintf("%s-%s-%d", row[0], row[1], caseFlag),
				func(t *testing.T) {
					expectedCaseResult := row[2+caseFlag]
					var want *secp.FieldVal
					if expectedCaseResult != "" {
						want = getFieldVal(expectedCaseResult)
					}

					got := XSwiftECInv(x, u, caseFlag)

					if want == nil {
						if got != nil {
							t.Fatalf("wanted nil but got something")
						}
						return
					}

					if got == nil {
						t.Fatalf("got nil but expected something")
					}

					if !got.Equals(want) {
						t.Fatalf("omg, got: %s   wanted: %s", got.String(), want.String())
					}
				},
			)
		}
	}
}

func TestXSwiftEC(t *testing.T) {
	testRecords := readCsvFile("ellswift_decode_test_vectors.csv")
	for _, row := range testRecords[1:] {
		t.Run(row[0],
			func(t *testing.T) {
				byteArray := mustDecodeHexStringToBytes(row[0])
				if len(byteArray) != 64 {
					t.Fatalf("buffer is wrong length, got: %d, want: 64", len(byteArray))
					return
				}
				b1 := byteArray[0:32]
				b2 := byteArray[32:]

				var tstU, tstT secp.FieldVal

				tstU.SetByteSlice(b1)
				tstT.SetByteSlice(b2)

				byteArrayCell2 := mustDecodeHexStringToBytes(row[1])
				if len(byteArrayCell2) != 32 {
					t.Fatalf("byteArrayCell2 is wrong length, got: %d, want: 64", len(byteArray))
					return
				}

				var wantX secp.FieldVal

				wantX.SetByteSlice(byteArrayCell2)
				wantX.Normalize()

				gotX, err := XSwiftEC(&tstU, &tstT)
				t.Logf("XSwiftEC() err: %s", err)

				if !gotX.Normalize().Equals(&wantX) {
					t.Errorf("not matching, got: %s  want: %s", gotX.String(), wantX.String())
				}
			},
		)
	}
}

func TestEllswiftEcdhXonly(t *testing.T) {
	for _, tst := range []struct {
		inPubKeyTheirs string
		inPrivKeyStr   string
		want           string
	}{
		{
			inPubKeyTheirs: "e8c09ba317c60087009b55d8a5badd0795f8926747c3fef405da799a82968c6def85ca36770eb73ffd8572ce2b4dcc6869a4b388d1d32d914114e4ff06cb8601",
			inPrivKeyStr:   "057e5a92b9df63d8c46a09fac662553c756b15c1fa0a3bf68e2cf96f1d719a15",
			want:           "58dd979b8c5aa75e72c8b565aff9574736ad4ec740fe33a08c5c01e32982f624",
		},
		{
			inPubKeyTheirs: "6ce872accebca744ffb1ac7d12b14e623d87e5dbe80e5494c0163814462e991d9f5fe240fd8fbdf40610a5b0fcf44a774fc9d1a773f346f69c77de8fbcfe8ab1",
			inPrivKeyStr:   "29f46a2bc9c11f7c9f518cc55974faf83e5cbe2d2d52121ee3d65542cf8687d7",
			want:           "371c6538c2f5c3fb5126d9ce7ef07e99d9631d2b6e190f54a92823f406135ee0",
		},
		{
			inPubKeyTheirs: "8a411de8eab0c225d17cd3ac20e9220e05569ba46866ac16211bf65fbf8774e70b9b2e799b62109b1f528de231e773c75455b1a989edd4ad8618b5ce93bf36ce",
			inPrivKeyStr:   "467baf576247df29c4d310e52b379dacb2296ac18f0d6a47f06ef0881c4534ad",
			want:           "eea33d81f071db1302466ad96b4526a358d0c4cbcdea5e51d7423356bc918ce5",
		},
	} {
		t.Run(fmt.Sprintf("%s", tst.want), func(t *testing.T) {
			pubkeyTheirs := mustDecodeHexStringToBytes(tst.inPubKeyTheirs)
			privkeyBytes := mustDecodeHexStringToBytes(tst.inPrivKeyStr)
			privKey := secp.PrivKeyFromBytes(privkeyBytes)

			ex, err := NewEllswiftExchangeFromKeys(privKey, GetEllswiftPubKey(privKey.PubKey()))
			if err != nil {
				t.Fatalf("NewEllswiftExchangeFromKeys err: %s", err)
			}

			res, err := ex.EllswiftEcdhXonly(pubkeyTheirs)
			if err != nil {
				t.Errorf("omg no: %s", err)
			}
			got := hex.EncodeToString(res)

			if got != tst.want {
				t.Errorf("not matching")
			}
		})
	}
}

func TestEllswiftComputeSharedSecret(t *testing.T) {
	for _, tst := range []struct {
		inPubKeyTheirs string
		inPrivKeyStr   string
		inPubKeyOurs   string
		init           bool
		want           string
	}{
		{
			inPubKeyTheirs: "bda17ec7cbcf7b515e24f8e018ff3dfaf072d16feba2ecb363f937b41f0a9056d4b28a948f867fd6ead84ee8d035bb4c1d5c71399370da67b88a9d9223f398a7",
			inPrivKeyStr:   "21d8742232e5dda33edfa789d46900c5c92bd42603e01de89121048bcf06c5a4",
			inPubKeyOurs:   "9bc8974074b5ef63cb9aa195e8362124b46b21246de6fb6b3828f1c4a44e2dc21255bce3aa6e965c717157b735e1a6692ba7893f6beb342e16c8353f6b2d5cb7",
			init:           true,
			want:           "f00dd09ab0e7baef06eb3cbd963d9eb86a2694e74fb715c40284f30d749e136e",
		},

		{
			inPubKeyTheirs: "00cbfb0a599dd26f37b678ae18cebb23f0d6c64ed4890ac63ea81919c7c25159c41825bb13e7a065d15f1be99907facdcf81635dd0ad5d3c74ae1f26f6633ae6",
			inPrivKeyStr:   "606904079c8358c5bf274c9ec934fe12c17e6777eb21dd12143387fe971925f2",
			inPubKeyOurs:   "9eb46834b3dd08cf81c4ff887d61e94c14848dbd2f81ef5f639b6f248e4a8f37b2b58984a122bee1ab757d18c30cac5976b59acc98f3070c73c52ab2d40e2864",
			init:           true,
			want:           "25b5d91bb6cddc01d1e46bff58aab6f0dc66c1929abc98c22cf424ec0aff57a5",
		},
		{
			inPubKeyTheirs: "9eb46834b3dd08cf81c4ff887d61e94c14848dbd2f81ef5f639b6f248e4a8f37b2b58984a122bee1ab757d18c30cac5976b59acc98f3070c73c52ab2d40e2864",
			inPrivKeyStr:   "cec0160920d420c99cc3404cc3a7732e536c1891b9103ac7b9e2ba5fc60ca8b4",
			inPubKeyOurs:   "00cbfb0a599dd26f37b678ae18cebb23f0d6c64ed4890ac63ea81919c7c25159c41825bb13e7a065d15f1be99907facdcf81635dd0ad5d3c74ae1f26f6633ae6",
			init:           false,
			want:           "25b5d91bb6cddc01d1e46bff58aab6f0dc66c1929abc98c22cf424ec0aff57a5",
		},
	} {
		t.Run(fmt.Sprintf("%s", tst.want), func(t *testing.T) {

			pubkeyTheirs := mustDecodeHexStringToBytes(tst.inPubKeyTheirs)
			pubkeyOurs := mustDecodeHexStringToBytes(tst.inPubKeyOurs)

			privkeyBytes := mustDecodeHexStringToBytes(tst.inPrivKeyStr)
			privKey := secp.PrivKeyFromBytes(privkeyBytes)

			ex, err := NewEllswiftExchangeFromKeys(privKey, pubkeyOurs)
			if err != nil {
				t.Fatalf("NewEllswiftExchangeFromKeys err: %s", err)
			}

			res, err := ex.ComputeSharedSecret(pubkeyTheirs, tst.init)
			if err != nil {
				t.Errorf("omg no: %s", err)
			}
			got := hex.EncodeToString(res)

			if got != tst.want {
				t.Errorf("not matching, got: %s", got)
			}
		})
	}
}

func TestEllswiftExchangeComputeSharedSecret(t *testing.T) {
	for _, tst := range []struct {
		inPubKeyOurs   string
		inPubKeyTheirs string
		inPrivKeyStr   string
		isInit         bool
		want           string
	}{
		{
			inPubKeyOurs:   "2fbe4bcdd647e67e26daf66f1ac0433e8791f8bbe2f2b151bd387d6724fe39eefe0993b39e82e0fc6fe1416455e7618c1c36b4ce50a0f453ea136d72aa63bf18",
			inPubKeyTheirs: "d43d5cc0194d2cd1f51008b1837347768c6b2f487a4dda435b29003faae937a811628799d7a20ecf38a2c1d4b4b5c96a183d1597f688ed9c5fcf2024c010a2fe",
			inPrivKeyStr:   "4308766c8f59277a50e858b1af1d1a51ce3d9abbd115b83e3dc84e08ad38321a",
			isInit:         true,
			want:           "3e6343bf67576a9302c7d6ad0dc35868e7abe446996864caca43d4761e947450",
		},
		{
			inPubKeyOurs:   "d43d5cc0194d2cd1f51008b1837347768c6b2f487a4dda435b29003faae937a811628799d7a20ecf38a2c1d4b4b5c96a183d1597f688ed9c5fcf2024c010a2fe",
			inPubKeyTheirs: "2fbe4bcdd647e67e26daf66f1ac0433e8791f8bbe2f2b151bd387d6724fe39eefe0993b39e82e0fc6fe1416455e7618c1c36b4ce50a0f453ea136d72aa63bf18",
			inPrivKeyStr:   "a06373da0b912accbe1a2ba3a362f40fa6e8c4a0114ca79862e12b5c87fb46a3",
			isInit:         false,
			want:           "3e6343bf67576a9302c7d6ad0dc35868e7abe446996864caca43d4761e947450",
		},

		{
			inPubKeyOurs:   "038438ff867f47e62d6c4c30d50ec7bbc1070eed41652b522fa657e5c39c061b8755012a2e0039e16ac993dbfa86feb28cf429c066b547136dd1d1e3d430beac",
			inPubKeyTheirs: "7f398f94caca6f2ec0ab726eacb7bb835c9733cf4bab2e0e8b1b3aede5b8cb2768169743bae83ff50d25efe0c281c8c6a2d84fea5520b2a1a71ef89b69b047d2",
			inPrivKeyStr:   "0b34fd949ad056b2cdd27f4b1413d4ea4c6e5b1ed6530c30dfd6e342685aae0e",
			isInit:         true,
			want:           "bcaba90f8cb47c876969cae0b62d1c8f3ea430d744d6a6d09686f4dc179209ed",
		},
		{
			inPubKeyOurs:   "7f398f94caca6f2ec0ab726eacb7bb835c9733cf4bab2e0e8b1b3aede5b8cb2768169743bae83ff50d25efe0c281c8c6a2d84fea5520b2a1a71ef89b69b047d2",
			inPubKeyTheirs: "038438ff867f47e62d6c4c30d50ec7bbc1070eed41652b522fa657e5c39c061b8755012a2e0039e16ac993dbfa86feb28cf429c066b547136dd1d1e3d430beac",
			inPrivKeyStr:   "527e58651681caee659ec0f732604c9f6b2407a17462fb4d22704cc33e55f826",
			isInit:         false,
			want:           "bcaba90f8cb47c876969cae0b62d1c8f3ea430d744d6a6d09686f4dc179209ed",
		},
	} {
		t.Run(fmt.Sprintf("%#v-%#v", tst.want, tst.isInit), func(t *testing.T) {

			privkeyBytes := mustDecodeHexStringToBytes(tst.inPrivKeyStr)
			pubkeyOurs := mustDecodeHexStringToBytes(tst.inPubKeyOurs)
			pubkeyTheirs := mustDecodeHexStringToBytes(tst.inPubKeyTheirs)

			ex, err := NewEllswiftExchangeFromKeys(secp.PrivKeyFromBytes(privkeyBytes), pubkeyOurs)
			if err != nil {
				t.Errorf("omg no: %s", err)
			}

			sharedSecret, err := ex.ComputeSharedSecret(pubkeyTheirs, tst.isInit)
			if err != nil {
				t.Errorf("omg no: %s", err)
			}

			got := hex.EncodeToString(sharedSecret)
			if got != tst.want {
				t.Errorf("not matching, got: %s   want: %s", got, tst.want)
			}
		})
	}
}

func TestEllswiftAliceAndBob(t *testing.T) {
	exAlice, err := NewEllswiftExchange()
	if err != nil {
		t.Errorf("Alice EllswiftCreate() err: %s", err)
	}

	exBob, err := NewEllswiftExchange()
	if err != nil {
		t.Errorf("Bob EllswiftCreate() err: %s", err)
	}

	sharedSecretAlice, err := exAlice.ComputeSharedSecret(exBob.ellswiftPubKey, true)
	if err != nil {
		t.Errorf("Alice bip324_ecdh() err: %s", err)
	}

	sharedSecretBob, err := exBob.ComputeSharedSecret(exAlice.ellswiftPubKey, false)
	if err != nil {
		t.Fatalf("Bob bip324_ecdh() err: %s", err)
	}

	if !bytes.Equal(sharedSecretAlice, sharedSecretBob) {
		t.Logf("expected shared secrets to match, got \nsharedSecretAlice: %#v \nsharedSecretBob:   %#v", sharedSecretAlice, sharedSecretBob)
	}
}
