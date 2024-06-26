package transport

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"net"

	bip324_crypto "github.com/lnliz/bitcoin-bip324-proxy/crypto"
)

const (
	maxGarbageLength = 4096
)

type V2Transport struct {
	remoteCon net.Conn
	cipher    *bip324_crypto.Bip324Cipher
	netMagic  []byte

	SendAadAndGarbage []byte
	RecvAad           []byte
}

func NewTransport(remoteCon net.Conn, netMagic []byte) (*V2Transport, error) {
	cipher, err := bip324_crypto.NewBip324Cipher(netMagic)
	if err != nil {
		return nil, err
	}
	return NewTransportWithCipher(remoteCon, netMagic, cipher), nil
}

func NewTransportWithCipher(remoteCon net.Conn, netMagic []byte, cipher *bip324_crypto.Bip324Cipher) *V2Transport {
	return &V2Transport{
		netMagic:          netMagic,
		cipher:            cipher,
		remoteCon:         remoteCon,
		SendAadAndGarbage: getRandomBytes(maxGarbageLength),
	}
}

func (t *V2Transport) SendV2Message(msg *P2pMessage) error {
	buf := msg.EncodeAsV2()
	return t.SendBip324Packet(t.remoteCon, buf, false)
}

func (t *V2Transport) lookForGarbage(nc net.Conn) error {
	garbageReceived, err := ReadData(nc, bip324_crypto.GarbageTerminatorLength)
	if err != nil {
		return err
	}

	terminatorFound := false
	for n := 0; n < maxGarbageLength; n++ {
		cmp := garbageReceived[len(garbageReceived)-bip324_crypto.GarbageTerminatorLength:]
		if bytes.Equal(cmp, t.cipher.RecvGarbageTerminator) {
			terminatorFound = true
			break
		}
		oneByte, err := ReadData(nc, 1)
		if err != nil {
			return err
		}
		garbageReceived = append(garbageReceived, oneByte...)
	}

	if !terminatorFound {
		return fmt.Errorf("initiatorGarbage terminator not found, we're done")
	}

	// strip terminator from result
	garbageReceived = garbageReceived[:len(garbageReceived)-bip324_crypto.GarbageTerminatorLength]
	t.RecvAad = garbageReceived

	return nil
}

func (t *V2Transport) MaybeSendDecoyPackets() (int, error) {
	packetsSent := 0

	// todo: allow configure how often decoy is sent
	// current config: 25% chance to send 1-25 decoys
	x := rand.Intn(100)
	for n := 75; n < x; n++ {
		decoyData := getRandomBytes(250)
		if err := t.SendBip324Packet(t.remoteCon, decoyData, true); err != nil {
			return packetsSent, err
		}
		packetsSent += 1
	}

	return packetsSent, nil
}

func (t *V2Transport) SendBip324Packet(nc net.Conn, packet []byte, ignore bool) error {
	encrPacket, err := t.cipher.EncryptPacketBuf(packet, t.SendAadAndGarbage, ignore)
	if err != nil {
		return err
	}
	t.SendAadAndGarbage = []byte{}

	return SendData(nc, encrPacket)
}

func (t *V2Transport) RecvBip324Packet(nc net.Conn) ([]byte, error) {
	for {
		encrLen, err := ReadData(nc, 3)
		if err != nil {
			return nil, err
		}

		length, err := t.cipher.DecryptPacketLen(encrLen)
		if err != nil {
			return nil, err
		}

		expectedPayloadLen := 1 + length + bip324_crypto.Expansion
		aeadCiphertext, err := ReadData(nc, expectedPayloadLen)
		if err != nil {
			return nil, err
		}

		plaintext, err := t.cipher.DecryptPacketBuf(aeadCiphertext, t.RecvAad)
		if err != nil {
			return nil, err
		}

		t.RecvAad = []byte{}

		header := plaintext[0]
		if header&bip324_crypto.HeaderIgnoreBit == bip324_crypto.HeaderIgnoreBit {
			// skipping a decoy packet with ignore bit
		} else {
			return plaintext[1 : length+1], nil
		}
	}
}

func (t *V2Transport) RecvV2Message() (*P2pMessage, error) {
	buf, err := t.RecvBip324Packet(t.remoteCon)
	if err != nil {
		return nil, err
	}
	return NewP2pMessageFromV2Buffer(buf)
}

func (t *V2Transport) receiveAndCheckTransportVersion() error {
	peerTransportVersion, err := t.RecvBip324Packet(t.remoteCon)
	if err != nil {
		return err
	}

	if !bytes.Equal(peerTransportVersion, bip324_crypto.TransportVersion) {
		return fmt.Errorf("unexpected peerTransportVersion: %#v", peerTransportVersion)
	}
	return nil
}

func (t *V2Transport) V2Handshake(isInit bool) error {
	/*
		try to establish an encrypted v2 connection
	*/
	if err := t.sendOurEllswiftPubKey(); err != nil {
		return err
	}

	if isInit {
		if err := SendData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("SendData(SendAadAndGarbage) err: %w", err)
		}
	}

	/*
		receive their ellswift key and initialize our cipher
	*/
	if err := t.recvTheirEllswiftPubKey(isInit); err != nil {
		return fmt.Errorf("recvTheirEllswiftPubKey() err: %w", err)
	}

	if isInit {
		if err := SendData(t.remoteCon, t.cipher.SendGarbageTerminator); err != nil {
			return fmt.Errorf("SendData(SendGarbageTerminator) err: %w", err)
		}

		if _, err := t.MaybeSendDecoyPackets(); err != nil {
			return fmt.Errorf("MaybeSendDecoyPackets() err: %w", err)
		}

		if err := t.lookForGarbage(t.remoteCon); err != nil {
			return fmt.Errorf("lookForGarbage() err: %w", err)
		}
	} else {
		if err := t.lookForGarbage(t.remoteCon); err != nil {
			return fmt.Errorf("lookForGarbage() err: %w", err)
		}

		if err := SendData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("SendData(SendAadAndGarbage) err: %w", err)
		}

		if err := SendData(t.remoteCon, t.cipher.SendGarbageTerminator); err != nil {
			return fmt.Errorf("SendData(SendGarbageTerminator) err: %w", err)
		}

		if _, err := t.MaybeSendDecoyPackets(); err != nil {
			return fmt.Errorf("MaybeSendDecoyPackets() err: %w", err)
		}
	}

	/*
		finally: check the TransportVersion
	*/
	if isInit {
		if err := t.receiveAndCheckTransportVersion(); err != nil {
			return fmt.Errorf("receiveAndCheckTransportVersion() err: %w", err)
		}

		if err := t.SendBip324Packet(t.remoteCon, bip324_crypto.TransportVersion, false); err != nil {
			return fmt.Errorf("SendBip324Packet(TransportVersion) err: %w", err)
		}
	} else {
		if err := t.SendBip324Packet(t.remoteCon, bip324_crypto.TransportVersion, false); err != nil {
			return fmt.Errorf("SendBip324Packet(TransportVersion) err: %w", err)
		}

		if err := t.receiveAndCheckTransportVersion(); err != nil {
			return fmt.Errorf("receiveAndCheckTransportVersion() err: %w", err)
		}
	}

	/*
		success: established a v2 connection
	*/
	return nil
}

func (t *V2Transport) sendOurEllswiftPubKey() error {
	return SendData(t.remoteCon, t.cipher.GetOurEllswiftPublicKey())
}

func (t *V2Transport) recvTheirEllswiftPubKey(initializing bool) error {
	theirEllswiftPubKey, err := ReadData(t.remoteCon, bip324_crypto.EllswiftPubKeyLength)
	if err != nil {
		return err
	}

	if err := t.cipher.Init(theirEllswiftPubKey, initializing); err != nil {
		return err
	}

	return nil
}

func getRandomBytes(maxSz int) []byte {
	sz := rand.Intn(maxSz)
	buf := make([]byte, sz)
	// todo: check the error
	crand.Read(buf)
	return buf
}
