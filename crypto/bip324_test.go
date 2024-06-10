package bip324_crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	tstNetMagicMainnet, _ = hex.DecodeString("f9beb4d9")
)

func TestPacketEncoding(t *testing.T) {
	testRecords := readCsvFile("packet_encoding_test_vectors.csv")
	for rowNum, row := range testRecords[1:] {
		t.Run(fmt.Sprintf("Row %d", rowNum), func(t *testing.T) {
			in_idx, err := strconv.Atoi(row[0])
			if err != nil {
				t.Fatalf("Error converting test record:  %s   err:  %s", row[0], err)
			}

			in_priv_ours := mustDecodeHexStringToBytes(row[1])
			in_ellswift_ours := mustDecodeHexStringToBytes(row[2])
			in_ellswift_theirs := mustDecodeHexStringToBytes(row[3])

			in_initiating := row[4] == "1"

			in_contents := mustDecodeHexStringToBytes(row[5])
			in_multiply, err := strconv.Atoi(row[6])
			if err != nil {
				t.Fatalf("Error converting test record:  %s   err:  %s", row[0], err)
			}
			in_aad := mustDecodeHexStringToBytes(row[7])

			in_ignore := row[8] == "1"

			// this is only for ellswift_ecdh_xonly()
			//mid_x_ours := mustDecodeHexStringToBytes(row[9])
			//mid_x_theirs := mustDecodeHexStringToBytes(row[10])

			mid_x_shared := mustDecodeHexStringToBytes(row[11])

			mid_shared_secret := mustDecodeHexStringToBytes(row[12])

			//mid_initiator_l := mustDecodeHexStringToBytes(row[13])
			//mid_initiator_p := mustDecodeHexStringToBytes(row[14])
			//mid_responder_l := mustDecodeHexStringToBytes(row[15])
			//mid_responder_p := mustDecodeHexStringToBytes(row[16])
			mid_send_garbage_terminator := mustDecodeHexStringToBytes(row[17])
			mid_recv_garbage_terminator := mustDecodeHexStringToBytes(row[18])
			out_session_id := mustDecodeHexStringToBytes(row[19])

			out_ciphertext := mustDecodeHexStringToBytes(row[20])
			out_ciphertext_endswith := mustDecodeHexStringToBytes(row[21])

			privKey := secp.PrivKeyFromBytes(in_priv_ours)
			ex, err := NewEllswiftExchangeFromKeys(privKey, in_ellswift_ours)
			if err != nil {
				t.Fatalf("NewEllswiftExchangeFromKeys err: %s", err)
			}

			ecdhPointX32, err := ex.EllswiftEcdhXonly(in_ellswift_theirs)
			if err != nil {
				t.Fatalf("ellswift_ecdh_xonly err: %s", err)
			}
			if !bytes.Equal(ecdhPointX32, mid_x_shared) {
				t.Logf("ecdhPointX32: %s", hex.EncodeToString(ecdhPointX32))
				t.Logf("mid_x_shared: %s", hex.EncodeToString(mid_x_shared))
				t.Fatalf("ellswift_ecdh_xonly ecdhPointX32 mismatch")
			}

			sharedSecret, err := ex.ComputeSharedSecret(in_ellswift_theirs, in_initiating)
			if err != nil {
				t.Fatalf("bip324_ecdh err: %s", err)
			}

			if !bytes.Equal(sharedSecret, mid_shared_secret) {
				t.Logf("sharedSecret: %s", hex.EncodeToString(sharedSecret))
				t.Logf("mid_shared_secret: %s", hex.EncodeToString(mid_shared_secret))
				t.Fatalf("bip324_ecdh shared_secret mismatch")
			}

			cipher := NewBip324CipherWithEllswiftExchange(tstNetMagicMainnet, ex)
			if err := cipher.Init(in_ellswift_theirs, in_initiating); err != nil {
				t.Fatalf("cipher.Init err: %s", err)
			}

			if !bytes.Equal(cipher.SendGarbageTerminator, mid_send_garbage_terminator) {
				t.Logf("send_garbage_terminator: %s", hex.EncodeToString(cipher.SendGarbageTerminator))
				t.Logf("mid_send_garbage_terminator: %s", hex.EncodeToString(mid_send_garbage_terminator))
				t.Fatalf(">>>>>>>> send_garbage_terminator mismatch")
			}
			if !bytes.Equal(cipher.RecvGarbageTerminator, mid_recv_garbage_terminator) {
				t.Logf("recv_garbage_terminator: %s", hex.EncodeToString(cipher.RecvGarbageTerminator))
				t.Logf("mid_recv_garbage_terminator: %s", hex.EncodeToString(mid_recv_garbage_terminator))
				t.Fatalf(">>>>>>>> mid_recv_garbage_terminator mismatch")
			}

			if !bytes.Equal(cipher.SessionId, out_session_id) {
				t.Fatalf("out_session_id mismatch")
			}

			// do number of dummy ops to fwd the index of the cipher
			for idx := 0; idx < in_idx; idx++ {
				_, err := cipher.EncryptPacketBuf([]byte{}, []byte{}, false)
				if err != nil {
					t.Fatalf("EncryptPacketBuf err: %s", err)
				}
			}

			var contents []byte
			for idx := 0; idx < in_multiply; idx++ {
				contents = append(contents, in_contents...)
			}

			sendData, err := cipher.EncryptPacketBuf(contents, in_aad, in_ignore)
			if err != nil {
				t.Fatalf("EncryptPacketBuf err: %s", err)
			}

			if len(out_ciphertext) > 0 {
				if !bytes.Equal(sendData, out_ciphertext) {
					t.Logf("sendData:       %s", hex.EncodeToString(sendData))
					t.Logf("out_ciphertext: %s", hex.EncodeToString(out_ciphertext))
					t.Fatalf("out_ciphertext not matching")
				}
			} else {
				if len(sendData) < len(out_ciphertext_endswith) {
					t.Logf("len(sendData): %d", len(sendData))
					t.Logf("len(out_ciphertext_endswith): %d", len(out_ciphertext_endswith))
					t.Fatalf("not enough data")
				} else {
					subsetOfSendData := sendData[len(sendData)-len(out_ciphertext_endswith):]
					if !bytes.Equal(subsetOfSendData, out_ciphertext_endswith) {
						t.Logf("subsetOfSendData:        %s", hex.EncodeToString(subsetOfSendData))
						t.Logf("out_ciphertext_endswith: %s", hex.EncodeToString(out_ciphertext_endswith))
						t.Fatalf("out_ciphertext_endswith not matching")
					}
				}
			}
		})
	}
}
