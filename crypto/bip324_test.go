package bip324_crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lnliz/bitcoin-bip324-proxy/fschacha20"
)

var (
	tstNetMagicMainnet uint32 = 0xd9b4bef9
)

func TestPacketEncoding(t *testing.T) {
	testRecords := readCsvFile(t, "packet_encoding_test_vectors.csv")
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

			mid_initiator_l := mustDecodeHexStringToBytes(row[13])
			mid_initiator_p := mustDecodeHexStringToBytes(row[14])
			mid_responder_l := mustDecodeHexStringToBytes(row[15])
			mid_responder_p := mustDecodeHexStringToBytes(row[16])
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

			cipher, err := NewBip324CipherWithEllswiftExchange(tstNetMagicMainnet, ex)
			if err != nil {
				t.Fatalf("NewBip324CipherWithEllswiftExchange err: %s", err)
			}
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

			recvLKey, recvPKey := mid_initiator_l, mid_initiator_p
			if !in_initiating {
				recvLKey, recvPKey = mid_responder_l, mid_responder_p
			}
			recvLCipher, err := fschacha20.NewFSChaCha20(recvLKey)
			if err != nil {
				t.Fatalf("NewFSChaCha20 receiver err: %s", err)
			}
			recvPCipher, err := fschacha20.NewFSChaCha20Poly1305(recvPKey)
			if err != nil {
				t.Fatalf("NewFSChaCha20Poly1305 receiver err: %s", err)
			}
			receiver := &Bip324Cipher{
				recvLCipher: recvLCipher,
				recvPCipher: recvPCipher,
			}

			// do number of dummy ops to fwd the index of the cipher
			for idx := 0; idx < in_idx; idx++ {
				dummy, err := cipher.EncryptPacketBuf(nil, nil, false)
				if err != nil {
					t.Fatalf("EncryptPacketBuf err: %s", err)
				}
				length, err := receiver.DecryptPacketLen(dummy[:LengthFieldLength])
				if err != nil {
					t.Fatalf("DecryptPacketLen dummy %d err: %s", idx, err)
				}
				if length != 0 {
					t.Fatalf("dummy packet %d length = %d, want 0", idx, length)
				}
				plaintext, err := receiver.DecryptPacketBuf(dummy[LengthFieldLength:], nil)
				if err != nil {
					t.Fatalf("DecryptPacketBuf dummy %d err: %s", idx, err)
				}
				if !bytes.Equal(plaintext, []byte{0}) {
					t.Fatalf("dummy packet %d plaintext = %x, want 00", idx, plaintext)
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

			decodedLength, err := receiver.DecryptPacketLen(sendData[:LengthFieldLength])
			if err != nil {
				t.Fatalf("DecryptPacketLen vector packet err: %s", err)
			}
			if decodedLength != len(contents) {
				t.Fatalf("decoded vector length = %d, want %d", decodedLength, len(contents))
			}
			plaintext, err := receiver.DecryptPacketBuf(sendData[LengthFieldLength:], in_aad)
			if err != nil {
				t.Fatalf("DecryptPacketBuf vector packet err: %s", err)
			}
			wantHeader := byte(0)
			if in_ignore {
				wantHeader = HeaderIgnoreBit
			}
			if plaintext[0] != wantHeader || !bytes.Equal(plaintext[1:], contents) {
				t.Fatalf("decrypted vector packet does not match header and contents")
			}
		})
	}
}

func TestPacketLengthValidation(t *testing.T) {
	cipher := &Bip324Cipher{}
	for _, in := range [][]byte{
		nil,
		{0x00, 0x01},
		{0x00, 0x01, 0x02, 0x03},
	} {
		_, err := cipher.DecryptPacketLen(in)
		if err == nil || !strings.Contains(err.Error(), "encrypted packet length") {
			t.Fatalf("DecryptPacketLen(%x) err = %v, want length error", in, err)
		}
	}
}

func TestEncryptPacketRejectsOversizedContents(t *testing.T) {
	sendLCipher, err := fschacha20.NewFSChaCha20(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewFSChaCha20 err: %s", err)
	}
	sendPCipher, err := fschacha20.NewFSChaCha20Poly1305(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 err: %s", err)
	}
	cipher := &Bip324Cipher{
		sendLCipher: sendLCipher,
		sendPCipher: sendPCipher,
	}

	_, err = cipher.EncryptPacketBuf(make([]byte, MaxPacketContentLength+1), nil, false)
	if err == nil || !strings.Contains(err.Error(), "packet contents too large") {
		t.Fatalf("EncryptPacketBuf oversized err = %v, want size error", err)
	}
}

func TestCipherPacketRoundTrip(t *testing.T) {
	initiator, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher initiator err: %s", err)
	}
	responder, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher responder err: %s", err)
	}

	if err := initiator.Init(responder.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("initiator Init err: %s", err)
	}
	if err := responder.Init(initiator.GetOurEllswiftPublicKey(), false); err != nil {
		t.Fatalf("responder Init err: %s", err)
	}
	if !bytes.Equal(initiator.SessionId, responder.SessionId) {
		t.Fatalf("session IDs differ")
	}
	if !bytes.Equal(initiator.SendGarbageTerminator, responder.RecvGarbageTerminator) ||
		!bytes.Equal(initiator.RecvGarbageTerminator, responder.SendGarbageTerminator) {
		t.Fatalf("directional garbage terminators do not match")
	}

	contents := []byte("application message")
	aad := []byte("handshake garbage")
	packet, err := initiator.EncryptPacketBuf(contents, aad, false)
	if err != nil {
		t.Fatalf("EncryptPacketBuf err: %s", err)
	}
	length, err := responder.DecryptPacketLen(packet[:LengthFieldLength])
	if err != nil {
		t.Fatalf("DecryptPacketLen err: %s", err)
	}
	if length != len(contents) {
		t.Fatalf("decoded length = %d, want %d", length, len(contents))
	}
	plaintext, err := responder.DecryptPacketBuf(packet[LengthFieldLength:], aad)
	if err != nil {
		t.Fatalf("DecryptPacketBuf err: %s", err)
	}
	if plaintext[0] != 0 || !bytes.Equal(plaintext[1:], contents) {
		t.Fatalf("decrypted packet = %x, want header 00 and contents %x", plaintext, contents)
	}
}

func TestNetworkMagicSeparatesCipherState(t *testing.T) {
	initiator, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher initiator err: %s", err)
	}
	responder, err := NewBip324Cipher(0x0709110b)
	if err != nil {
		t.Fatalf("NewBip324Cipher responder err: %s", err)
	}

	if err := initiator.Init(responder.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("initiator Init err: %s", err)
	}
	if err := responder.Init(initiator.GetOurEllswiftPublicKey(), false); err != nil {
		t.Fatalf("responder Init err: %s", err)
	}
	if bytes.Equal(initiator.SessionId, responder.SessionId) {
		t.Fatalf("different network magic produced the same session ID")
	}
	if bytes.Equal(initiator.SendGarbageTerminator, responder.RecvGarbageTerminator) {
		t.Fatalf("different network magic produced matching garbage terminators")
	}

	packet, err := initiator.EncryptPacketBuf([]byte("message"), nil, false)
	if err != nil {
		t.Fatalf("EncryptPacketBuf err: %s", err)
	}
	if _, err := responder.DecryptPacketBuf(packet[LengthFieldLength:], nil); err == nil {
		t.Fatalf("packet authenticated across different network magic")
	}
}

func TestFirstPacketAuthenticatesGarbage(t *testing.T) {
	initiator, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher initiator err: %s", err)
	}
	responder, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher responder err: %s", err)
	}
	if err := initiator.Init(responder.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("initiator Init err: %s", err)
	}
	if err := responder.Init(initiator.GetOurEllswiftPublicKey(), false); err != nil {
		t.Fatalf("responder Init err: %s", err)
	}

	packet, err := initiator.EncryptPacketBuf(nil, []byte("sent garbage"), false)
	if err != nil {
		t.Fatalf("EncryptPacketBuf err: %s", err)
	}
	if _, err := responder.DecryptPacketLen(packet[:LengthFieldLength]); err != nil {
		t.Fatalf("DecryptPacketLen err: %s", err)
	}
	if _, err := responder.DecryptPacketBuf(packet[LengthFieldLength:], []byte("modified garbage")); err == nil {
		t.Fatalf("first packet authenticated with modified garbage")
	}
}

func TestCipherInitializationIsOneShotAndDestroysEphemeralKey(t *testing.T) {
	privKeyBytes := make([]byte, 32)
	privKeyBytes[31] = 1
	callerPrivateKey := secp.PrivKeyFromBytes(privKeyBytes)
	publicKey, err := GetEllswiftPubKey(callerPrivateKey.PubKey())
	if err != nil {
		t.Fatalf("GetEllswiftPubKey err: %s", err)
	}
	exchange, err := NewEllswiftExchangeFromKeys(callerPrivateKey, publicKey)
	if err != nil {
		t.Fatalf("NewEllswiftExchangeFromKeys err: %s", err)
	}
	cipher, err := NewBip324CipherWithEllswiftExchange(tstNetMagicMainnet, exchange)
	if err != nil {
		t.Fatalf("NewBip324CipherWithEllswiftExchange err: %s", err)
	}
	peer, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher peer err: %s", err)
	}

	if err := cipher.Init(peer.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("Init err: %s", err)
	}
	if exchange.privKey != nil {
		t.Fatalf("ephemeral private key remains reachable after Init")
	}
	if callerPrivateKey.Key.IsZero() {
		t.Fatalf("Init erased the caller-owned private key")
	}
	if len(cipher.GetOurEllswiftPublicKey()) != EllswiftPubKeyLength {
		t.Fatalf("public encoding was not retained after private-key destruction")
	}
	if err := cipher.Init(peer.GetOurEllswiftPublicKey(), true); err == nil {
		t.Fatalf("Init succeeded twice")
	}
}

func TestCipherRejectsInvalidState(t *testing.T) {
	if _, err := NewBip324CipherWithEllswiftExchange(tstNetMagicMainnet, nil); err == nil {
		t.Fatalf("NewBip324CipherWithEllswiftExchange accepted nil exchange")
	}

	cipher := &Bip324Cipher{}
	if err := cipher.Init(make([]byte, EllswiftPubKeyLength), true); err == nil {
		t.Fatalf("Init accepted a cipher without an exchange")
	}
	if _, err := cipher.DecryptPacketBuf(make([]byte, Expansion), nil); err == nil {
		t.Fatalf("DecryptPacketBuf accepted an uninitialized cipher")
	}

	var nilCipher *Bip324Cipher
	if _, err := nilCipher.DecryptPacketLen(make([]byte, LengthFieldLength)); err == nil {
		t.Fatalf("DecryptPacketLen on nil receiver did not return an error")
	}
	if _, err := nilCipher.DecryptPacketBuf(make([]byte, Expansion+1), nil); err == nil {
		t.Fatalf("DecryptPacketBuf on nil receiver did not return an error")
	}
	if _, err := nilCipher.EncryptPacketBuf(nil, nil, false); err == nil {
		t.Fatalf("EncryptPacketBuf on nil receiver did not return an error")
	}
}

func TestCipherDestroyClearsReachableState(t *testing.T) {
	cipher, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher err: %s", err)
	}
	peer, err := NewBip324Cipher(tstNetMagicMainnet)
	if err != nil {
		t.Fatalf("NewBip324Cipher peer err: %s", err)
	}
	if err := cipher.Init(peer.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("Init err: %s", err)
	}

	sessionBacking := cipher.SessionId
	sendTermBacking := cipher.SendGarbageTerminator
	recvTermBacking := cipher.RecvGarbageTerminator
	sessionCopy := cipher.SessionID()
	if len(sessionCopy) != 32 || &sessionCopy[0] == &sessionBacking[0] {
		t.Fatalf("SessionID did not return an independent copy")
	}
	if cipher.NetworkMagic() != tstNetMagicMainnet {
		t.Fatalf("NetworkMagic = 0x%08x", cipher.NetworkMagic())
	}

	cipher.Destroy()
	for name, backing := range map[string][]byte{
		"session":            sessionBacking,
		"send terminator":    sendTermBacking,
		"receive terminator": recvTermBacking,
	} {
		if !bytes.Equal(backing, make([]byte, len(backing))) {
			t.Fatalf("%s backing memory was not cleared", name)
		}
	}
	if cipher.SessionID() != nil || cipher.GetOurEllswiftPublicKey() != nil {
		t.Fatalf("Destroy retained public session state")
	}
	if _, err := cipher.EncryptPacketBuf(nil, nil, false); err == nil {
		t.Fatalf("Destroy left the send cipher usable")
	}
	if _, err := cipher.DecryptPacketLen(make([]byte, LengthFieldLength)); err == nil {
		t.Fatalf("Destroy left the receive cipher usable")
	}
}
