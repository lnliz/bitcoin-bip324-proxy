package bip324_crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/lnliz/bitcoin-bip324-proxy/fschacha20"
)

const (
	GarbageTerminatorLength = 16
	HeaderIgnoreBit         = 0x80
	Expansion               = 16
	LengthFieldLength       = 3
	MaxPacketContentLength  = 1<<24 - 1
	TransportVersion        = ""
)

type Bip324Cipher struct {
	btcNet uint32
	ex     *EllswiftExchange

	SessionId             []byte
	SendGarbageTerminator []byte
	RecvGarbageTerminator []byte

	sendLCipher *fschacha20.FSChaCha20
	sendPCipher *fschacha20.FSChaCha20Poly1305

	recvLCipher *fschacha20.FSChaCha20
	recvPCipher *fschacha20.FSChaCha20Poly1305
	initialized bool
}

func NewBip324Cipher(btcNet uint32) (*Bip324Cipher, error) {
	ex, err := NewEllswiftExchange()
	if err != nil {
		return nil, err
	}

	return NewBip324CipherWithEllswiftExchange(btcNet, ex)
}

func NewBip324CipherWithEllswiftExchange(btcNet uint32, ex *EllswiftExchange) (*Bip324Cipher, error) {
	if ex == nil || ex.privKey == nil {
		return nil, fmt.Errorf("ellswift exchange is not initialized")
	}

	return &Bip324Cipher{
		ex:     ex,
		btcNet: btcNet,
	}, nil
}

func (c *Bip324Cipher) GetOurEllswiftPublicKey() []byte {
	if c == nil || c.ex == nil {
		return nil
	}
	return append([]byte(nil), c.ex.ellswiftPubKey[:]...)
}

func (c *Bip324Cipher) NetworkMagic() uint32 {
	if c == nil {
		return 0
	}
	return c.btcNet
}

func (c *Bip324Cipher) Initialized() bool {
	return c != nil && c.initialized
}

func (c *Bip324Cipher) SessionID() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.SessionId...)
}

// Destroy removes all reachable key material. Go's cryptographic primitives
// do not expose their internal key storage, so this is necessarily best effort.
func (c *Bip324Cipher) Destroy() {
	if c == nil {
		return
	}
	if c.ex != nil {
		c.ex.destroyPrivateKey()
		c.ex = nil
	}
	clear(c.SessionId)
	clear(c.SendGarbageTerminator)
	clear(c.RecvGarbageTerminator)
	c.SessionId = nil
	c.SendGarbageTerminator = nil
	c.RecvGarbageTerminator = nil
	c.sendLCipher = nil
	c.sendPCipher = nil
	c.recvLCipher = nil
	c.recvPCipher = nil
	c.initialized = false
}

func (c *Bip324Cipher) Init(theirEllswiftPubKey []byte, initiating bool) error {
	if c == nil || c.ex == nil {
		return fmt.Errorf("cipher has no ellswift exchange")
	}
	if c.initialized {
		return fmt.Errorf("cipher is already initialized")
	}

	sharedSecret, err := c.ex.ComputeSharedSecret(theirEllswiftPubKey, initiating)
	if err != nil {
		return err
	}
	c.ex.destroyPrivateKey()
	defer clear(sharedSecret)

	if err := c.initFromSharedSecret(sharedSecret, initiating); err != nil {
		return err
	}
	c.initialized = true

	return nil
}

func (c *Bip324Cipher) DecryptPacketLen(encrLen []byte) (int, error) {
	if len(encrLen) != LengthFieldLength {
		return 0, fmt.Errorf("encrypted packet length must be %d bytes, got %d", LengthFieldLength, len(encrLen))
	}
	if c == nil || c.recvLCipher == nil {
		return 0, fmt.Errorf("cipher is not initialized")
	}

	x, err := c.recvLCipher.Crypt(encrLen)
	if err != nil {
		return 0, err
	}

	var decoded [4]byte
	copy(decoded[:], x)
	length := int(binary.LittleEndian.Uint32(decoded[:]))

	return length, nil
}

func (c *Bip324Cipher) DecryptPacketBuf(encrPacket []byte, aad []byte) ([]byte, error) {
	if c == nil || c.recvPCipher == nil {
		return nil, fmt.Errorf("cipher is not initialized")
	}
	if len(encrPacket) < Expansion+1 {
		return nil, fmt.Errorf("encrypted packet must contain a header and authentication tag")
	}

	buf, err := c.recvPCipher.Decrypt(aad, encrPacket)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Bip324Cipher) EncryptPacketBuf(contents []byte, aad []byte, ignore bool) ([]byte, error) {
	if len(contents) > MaxPacketContentLength {
		return nil, fmt.Errorf("packet contents too large: %d > %d", len(contents), MaxPacketContentLength)
	}
	if c == nil || c.sendPCipher == nil || c.sendLCipher == nil {
		return nil, fmt.Errorf("cipher is not initialized")
	}

	plaintext := make([]byte, 1+len(contents))
	if ignore {
		plaintext[0] = HeaderIgnoreBit
	}
	copy(plaintext[1:], contents)
	aeadCiphertext, err := c.sendPCipher.Encrypt(aad, plaintext)
	if err != nil {
		return nil, err
	}

	var l [4]byte
	binary.LittleEndian.PutUint32(l[:4], uint32(len(contents)))
	encrLen, err := c.sendLCipher.Crypt(l[:3])
	if err != nil {
		return nil, err
	}

	return append(encrLen, aeadCiphertext...), nil
}

func (c *Bip324Cipher) initFromSharedSecret(sharedSecret []byte, initiating bool) error {
	nm := make([]byte, 4)
	binary.LittleEndian.PutUint32(nm, c.btcNet)
	salt := append([]byte("bitcoin_v2_shared_secret"), nm...)
	prk, err := hkdf.Extract(sha256.New, sharedSecret, salt)
	if err != nil {
		return err
	}
	defer clear(prk)

	derive := func(info string) ([]byte, error) {
		return hkdf.Expand(sha256.New, prk, info, 32)
	}

	gt, err := derive("garbage_terminators")
	if err != nil {
		return err
	}
	defer clear(gt)

	initiatorL, err := derive("initiator_L")
	if err != nil {
		return err
	}
	defer clear(initiatorL)
	initiatorP, err := derive("initiator_P")
	if err != nil {
		return err
	}
	defer clear(initiatorP)
	responderL, err := derive("responder_L")
	if err != nil {
		return err
	}
	defer clear(responderL)
	responderP, err := derive("responder_P")
	if err != nil {
		return err
	}
	defer clear(responderP)

	sessionID, err := derive("session_id")
	if err != nil {
		return err
	}
	defer clear(sessionID)

	sendLKey, sendPKey := initiatorL, initiatorP
	recvLKey, recvPKey := responderL, responderP
	sendTerminator := gt[:GarbageTerminatorLength]
	recvTerminator := gt[GarbageTerminatorLength:]
	if !initiating {
		sendLKey, sendPKey = responderL, responderP
		recvLKey, recvPKey = initiatorL, initiatorP
		sendTerminator, recvTerminator = recvTerminator, sendTerminator
	}

	sendLCipher, err := fschacha20.NewFSChaCha20(sendLKey)
	if err != nil {
		return err
	}
	sendPCipher, err := fschacha20.NewFSChaCha20Poly1305(sendPKey)
	if err != nil {
		return err
	}
	recvLCipher, err := fschacha20.NewFSChaCha20(recvLKey)
	if err != nil {
		return err
	}
	recvPCipher, err := fschacha20.NewFSChaCha20Poly1305(recvPKey)
	if err != nil {
		return err
	}

	clear(c.SessionId)
	clear(c.SendGarbageTerminator)
	clear(c.RecvGarbageTerminator)
	c.SessionId = append([]byte(nil), sessionID...)
	c.SendGarbageTerminator = append([]byte(nil), sendTerminator...)
	c.RecvGarbageTerminator = append([]byte(nil), recvTerminator...)
	c.sendLCipher = sendLCipher
	c.sendPCipher = sendPCipher
	c.recvLCipher = recvLCipher
	c.recvPCipher = recvPCipher

	return nil
}
