package fschacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RekeyInterval = 224
	KeySize       = chacha20poly1305.KeySize
	ChunkSize     = 3
)

type FSChaCha20 struct {
	chunkCounter uint64
	stream       *chacha20.Cipher
}

func NewFSChaCha20(initialKey []byte) (*FSChaCha20, error) {
	if len(initialKey) != KeySize {
		return nil, fmt.Errorf("FSChaCha20 key must be %d bytes, got %d", KeySize, len(initialKey))
	}

	stream, err := newLengthCipher(initialKey, 0)
	if err != nil {
		return nil, err
	}
	return &FSChaCha20{stream: stream}, nil
}

func newLengthCipher(key []byte, rekeyCount uint64) (*chacha20.Cipher, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], rekeyCount)
	return chacha20.NewUnauthenticatedCipher(key, nonce[:])
}

// Crypt encrypts or decrypts one BIP324 packet-length field.
func (c *FSChaCha20) Crypt(chunk []byte) ([]byte, error) {
	if c == nil || c.stream == nil {
		return nil, fmt.Errorf("FSChaCha20 is not initialized")
	}
	if len(chunk) != ChunkSize {
		return nil, fmt.Errorf("FSChaCha20 chunk must be %d bytes, got %d", ChunkSize, len(chunk))
	}
	if c.chunkCounter == math.MaxUint64 {
		return nil, fmt.Errorf("FSChaCha20 chunk counter exhausted")
	}

	result := make([]byte, len(chunk))
	c.stream.XORKeyStream(result, chunk)

	if (c.chunkCounter+1)%RekeyInterval == 0 {
		var newKey [KeySize]byte
		c.stream.XORKeyStream(newKey[:], newKey[:])
		stream, err := newLengthCipher(newKey[:], (c.chunkCounter+1)/RekeyInterval)
		if err != nil {
			clear(newKey[:])
			return nil, err
		}
		c.stream = stream
		clear(newKey[:])
	}
	c.chunkCounter++
	return result, nil
}

type FSChaCha20Poly1305 struct {
	aead          cipher.AEAD
	packetCounter uint64
}

func NewFSChaCha20Poly1305(initialKey []byte) (*FSChaCha20Poly1305, error) {
	if len(initialKey) != KeySize {
		return nil, fmt.Errorf("FSChaCha20Poly1305 key must be %d bytes, got %d", KeySize, len(initialKey))
	}

	aead, err := chacha20poly1305.New(initialKey)
	if err != nil {
		return nil, err
	}
	return &FSChaCha20Poly1305{aead: aead}, nil
}

func (cc *FSChaCha20Poly1305) crypt(aad []byte, text []byte, decrypt bool) ([]byte, error) {
	if cc == nil || cc.aead == nil {
		return nil, fmt.Errorf("FSChaCha20Poly1305 is not initialized")
	}
	if cc.packetCounter == math.MaxUint64 {
		return nil, fmt.Errorf("FSChaCha20Poly1305 packet counter exhausted")
	}

	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[:4], uint32(cc.packetCounter%RekeyInterval))
	binary.LittleEndian.PutUint64(nonce[4:], cc.packetCounter/RekeyInterval)

	var (
		ret      []byte
		cryptErr error
	)
	if decrypt {
		ret, cryptErr = cc.aead.Open(nil, nonce[:], text, aad)
	} else {
		ret = cc.aead.Seal(nil, nonce[:], text, aad)
	}

	if (cc.packetCounter+1)%RekeyInterval == 0 {
		if err := cc.rekey(nonce); err != nil {
			return nil, err
		}
	}
	cc.packetCounter++
	if cryptErr != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", cryptErr)
	}

	return ret, nil
}

func (cc *FSChaCha20Poly1305) Encrypt(aad []byte, plaintext []byte) ([]byte, error) {
	return cc.crypt(aad, plaintext, false)
}

func (cc *FSChaCha20Poly1305) Decrypt(aad []byte, ciphertext []byte) ([]byte, error) {
	return cc.crypt(aad, ciphertext, true)
}

func (cc *FSChaCha20Poly1305) rekey(nonce [12]byte) error {
	binary.LittleEndian.PutUint32(nonce[:4], ^uint32(0))
	var plaintext [KeySize]byte
	keyMaterial := cc.aead.Seal(nil, nonce[:], plaintext[:], nil)

	newAEAD, err := chacha20poly1305.New(keyMaterial[:KeySize])
	if err != nil {
		clear(keyMaterial)
		return err
	}
	cc.aead = newAEAD
	clear(keyMaterial)
	return nil
}
