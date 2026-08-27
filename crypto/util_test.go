package bip324_crypto

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestOfficialVectorChecksums(t *testing.T) {
	checksums := map[string]string{
		"ellswift_decode_test_vectors.csv": "a238a66b093bed3c571d5b57cb2bb1f69487788f0f872f7ea7501b5b98be20b0",
		"xswiftec_inv_test_vectors.csv":    "b5e8e0e9edfdee14c3ec4db3c6763543a9f17290a84a93de0ae2671c16f4432a",
		"packet_encoding_test_vectors.csv": "61704507945e2fa99e6c799fab888593eb7a2c3d2018f42ee4a3c3abe0684269",
	}

	for file, want := range checksums {
		t.Run(file, func(t *testing.T) {
			contents, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read official vector file: %s", err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != want {
				t.Fatalf("SHA-256 = %s, want %s", got, want)
			}
		})
	}
}

func mustDecodeHexStringToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func readCsvFile(t testing.TB, filePath string) [][]string {
	t.Helper()
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("read vector file %s: %s", filePath, err)
	}
	defer func() { _ = f.Close() }()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("parse vector file %s: %s", filePath, err)
	}

	return records
}

func getFieldVal(s string) *secp.FieldVal {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	var res secp.FieldVal
	res.SetByteSlice(b)

	return &res
}
