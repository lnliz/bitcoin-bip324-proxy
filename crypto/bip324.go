package bip324_crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/lnliz/bitcoin-bip324-proxy/fschacha20"
)

const (
	GarbageTerminatorLength = 16
	HeaderIgnoreBit         = 0x80
	Expansion               = 16
)

var (
	TransportVersion = []byte{}
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
}

func NewBip324Cipher(btcNet uint32) (*Bip324Cipher, error) {
	ex, err := NewEllswiftExchange()
	if err != nil {
		return nil, err
	}

	return NewBip324CipherWithEllswiftExchange(btcNet, ex), nil
}

func NewBip324CipherWithEllswiftExchange(btcNet uint32, ex *EllswiftExchange) *Bip324Cipher {
	return &Bip324Cipher{
		ex:     ex,
		btcNet: btcNet,
	}
}

func (c *Bip324Cipher) GetOurEllswiftPublicKey() []byte {
	return c.ex.ellswiftPubKey
}

func (c *Bip324Cipher) Init(theirEllswiftPubKey []byte, initiating bool) error {
	sharedSecret, err := c.ex.ComputeSharedSecret(theirEllswiftPubKey, initiating)
	if err != nil {
		return err
	}

	c.initFromSharedSecret(sharedSecret, initiating)

	/*
		erase sharedSecret from memory
	*/
	for idx := range sharedSecret {
		sharedSecret[idx] = 0
	}

	return nil
}

func (c *Bip324Cipher) DecryptPacketLen(encrLen []byte) (int, error) {
	x, err := c.recvLCipher.Crypt(encrLen)
	if err != nil {
		return 0, err
	}

	length := int(binary.LittleEndian.Uint32(append(x, 0)))

	return length, nil
}

func (c *Bip324Cipher) DecryptPacketBuf(encrPacket []byte, aad []byte) ([]byte, error) {
	buf, err := c.recvPCipher.Decrypt(aad, encrPacket)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Bip324Cipher) EncryptPacketBuf(contents []byte, aad []byte, ignore bool) ([]byte, error) {
	header := []byte("\x00")
	if ignore {
		header[0] = HeaderIgnoreBit
	}

	plaintext := append(header, contents...)
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

func (c *Bip324Cipher) initFromSharedSecret(sharedSecret []byte, initiating bool) {
	nm := make([]byte, 4)
	binary.LittleEndian.PutUint32(nm, c.btcNet)
	salt := append([]byte("bitcoin_v2_shared_secret"), nm...)
	gt := hkdfSHA256(32, sharedSecret, salt, []byte("garbage_terminators"))

	initiatorL := hkdfSHA256(32, sharedSecret, salt, []byte("initiator_L"))
	initiatorP := hkdfSHA256(32, sharedSecret, salt, []byte("initiator_P"))
	responderL := hkdfSHA256(32, sharedSecret, salt, []byte("responder_L"))
	responderP := hkdfSHA256(32, sharedSecret, salt, []byte("responder_P"))

	c.SessionId = hkdfSHA256(32, sharedSecret, salt, []byte("session_id"))

	if initiating {
		c.SendGarbageTerminator = gt[:GarbageTerminatorLength]
		c.RecvGarbageTerminator = gt[GarbageTerminatorLength:]

		c.sendLCipher = fschacha20.NewFSChaCha20(initiatorL)
		c.sendPCipher = fschacha20.NewFSChaCha20Poly1305(initiatorP)

		c.recvLCipher = fschacha20.NewFSChaCha20(responderL)
		c.recvPCipher = fschacha20.NewFSChaCha20Poly1305(responderP)
	} else {
		c.SendGarbageTerminator = gt[GarbageTerminatorLength:]
		c.RecvGarbageTerminator = gt[:GarbageTerminatorLength]

		c.sendLCipher = fschacha20.NewFSChaCha20(responderL)
		c.sendPCipher = fschacha20.NewFSChaCha20Poly1305(responderP)

		c.recvLCipher = fschacha20.NewFSChaCha20(initiatorL)
		c.recvPCipher = fschacha20.NewFSChaCha20Poly1305(initiatorP)
	}
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hkdfSHA256(length int, ikm, salt, info []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	prk := hmacSHA256(salt, ikm)
	t := []byte{}
	okm := []byte{}
	for i := 0; i < (length+32-1)/32; i++ {
		t = hmacSHA256(prk, append(append(t, info...), byte(i+1)))
		okm = append(okm, t...)
	}
	return okm[:length]
}
