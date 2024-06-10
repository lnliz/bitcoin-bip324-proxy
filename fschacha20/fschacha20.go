package fschacha20

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RekeyInterval = 224
)

type FSChaCha20 struct {
	key          []byte
	blockCounter uint32
	chunkCounter uint64
	keystream    []byte
}

func NewFSChaCha20(initialKey []byte) *FSChaCha20 {
	return &FSChaCha20{
		key:       initialKey,
		keystream: make([]byte, 0),
	}
}

func (c *FSChaCha20) getKeystreamBytes(nbytes int) ([]byte, error) {
	for len(c.keystream) < nbytes {
		var nonce [12]byte
		binary.LittleEndian.PutUint32(nonce[:4], 0)
		binary.LittleEndian.PutUint64(nonce[4:], c.chunkCounter/RekeyInterval)

		stream, err := chacha20.NewUnauthenticatedCipher(c.key, nonce[:])
		if err != nil {
			return nil, err
		}

		block := make([]byte, 64)
		stream.SetCounter(c.blockCounter)
		stream.XORKeyStream(block, block)

		c.keystream = append(c.keystream, block[:]...)
		c.blockCounter++
	}
	ret := c.keystream[:nbytes]
	c.keystream = c.keystream[nbytes:]
	return ret, nil
}

// Crypt encrypts/decrypts the given chunk
func (c *FSChaCha20) Crypt(chunk []byte) ([]byte, error) {
	keystreamBytes, err := c.getKeystreamBytes(len(chunk))
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(chunk))
	for i := range chunk {
		result[i] = chunk[i] ^ keystreamBytes[i]
	}
	if (c.chunkCounter+1)%RekeyInterval == 0 {
		newKey, err := c.getKeystreamBytes(32)
		if err != nil {
			return nil, err
		}
		copy(c.key[:], newKey)
		c.blockCounter = 0
	}
	c.chunkCounter++
	return result, nil
}

type FSChaCha20Poly1305 struct {
	key           []byte
	rekeyInterval uint64
	packetCounter uint64
}

func NewFSChaCha20Poly1305(initialKey []byte) *FSChaCha20Poly1305 {
	return &FSChaCha20Poly1305{
		key:           initialKey,
		rekeyInterval: RekeyInterval,
		packetCounter: 0,
	}
}

func (cc *FSChaCha20Poly1305) crypt(aad []byte, text []byte, is_decrypt bool) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[:4], uint32(cc.packetCounter%cc.rekeyInterval))
	binary.LittleEndian.PutUint64(nonce[4:], cc.packetCounter/cc.rekeyInterval)

	var err error
	var ret []byte

	if is_decrypt {
		ret, err = aeadChacha20Poly1305Decrypt(cc.key, nonce, aad, text)
	} else {
		ret, err = aeadChacha20Poly1305Encrypt(cc.key, nonce, aad, text)
	}

	if err != nil {
		return nil, err
	}

	if (cc.packetCounter+1)%RekeyInterval == 0 {
		if err2 := cc.rekey(nonce); err2 != nil {
			return nil, err2
		}
	}
	cc.packetCounter += 1

	return ret, nil
}

func (cc *FSChaCha20Poly1305) Encrypt(aad []byte, plaintext []byte) ([]byte, error) {
	return cc.crypt(aad, plaintext, false)
}

func (cc *FSChaCha20Poly1305) Decrypt(aad []byte, ciphertext []byte) ([]byte, error) {
	return cc.crypt(aad, ciphertext, true)
}

func (cc *FSChaCha20Poly1305) rekey(nonce [12]byte) error {
	nonce[0] = 0xFF
	nonce[1] = 0xFF
	nonce[2] = 0xFF
	nonce[3] = 0xFF
	empty32BytesOfPlaintext := make([]byte, 32)
	newKey, err := aeadChacha20Poly1305Encrypt(cc.key, nonce, []byte{}, empty32BytesOfPlaintext)
	if err != nil {
		return err
	}

	cc.key = newKey[:32]
	return nil
}

// aeadChacha20Poly1305Encrypt encrypts the plaintext with the given key, nonce, and aad.
func aeadChacha20Poly1305Encrypt(key []byte, nonce [12]byte, aad []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	return ciphertext, nil
}

// aeadChacha20Poly1305Decrypt decrypts the ciphertext with the given key, nonce, and aad.
func aeadChacha20Poly1305Decrypt(key []byte, nonce [12]byte, aad []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
