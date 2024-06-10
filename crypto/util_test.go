package bip324_crypto

import (
	"encoding/csv"
	"encoding/hex"
	"log"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func mustDecodeHexStringToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func readCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal("Unable to read input file "+filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+filePath, err)
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
