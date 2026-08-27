package fschacha20

import (
	"bytes"
	"encoding/binary"
	"math"
	"strconv"
	"testing"
)

func TestFSChaCha20CopiesInitialKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	cipher, err := NewFSChaCha20(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20 err: %s", err)
	}
	key[0] = 0xff

	got, err := cipher.Crypt([]byte{0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Crypt err: %s", err)
	}

	wantCipher, err := NewFSChaCha20(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("NewFSChaCha20 err: %s", err)
	}
	want, err := wantCipher.Crypt([]byte{0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("want Crypt err: %s", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("cipher used mutated caller key, got %x want %x", got, want)
	}
}

func TestFSChaCha20Poly1305CopiesInitialKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, 32)
	cipher, err := NewFSChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 err: %s", err)
	}
	key[0] = 0xff

	got, err := cipher.Encrypt(nil, []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt err: %s", err)
	}

	wantCipher, err := NewFSChaCha20Poly1305(bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 err: %s", err)
	}
	want, err := wantCipher.Encrypt(nil, []byte("payload"))
	if err != nil {
		t.Fatalf("want Encrypt err: %s", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("cipher used mutated caller key, got %x want %x", got, want)
	}
}

func TestConstructorsRejectInvalidKeys(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			if _, err := NewFSChaCha20(make([]byte, size)); err == nil {
				t.Fatalf("NewFSChaCha20 accepted a %d-byte key", size)
			}
			if _, err := NewFSChaCha20Poly1305(make([]byte, size)); err == nil {
				t.Fatalf("NewFSChaCha20Poly1305 accepted a %d-byte key", size)
			}
		})
	}
}

func TestFSChaCha20RejectsWrongChunkSize(t *testing.T) {
	cipher, err := NewFSChaCha20(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("NewFSChaCha20 err: %s", err)
	}

	for _, size := range []int{0, ChunkSize - 1, ChunkSize + 1} {
		if _, err := cipher.Crypt(make([]byte, size)); err == nil {
			t.Fatalf("Crypt accepted a %d-byte chunk", size)
		}
	}
}

func TestFSChaCha20RoundTripAcrossRekeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeySize)
	encrypter, err := NewFSChaCha20(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20 encrypter err: %s", err)
	}
	decrypter, err := NewFSChaCha20(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20 decrypter err: %s", err)
	}

	for i := uint32(0); i < 2*RekeyInterval+3; i++ {
		var plaintext [4]byte
		binary.LittleEndian.PutUint32(plaintext[:], i)
		ciphertext, err := encrypter.Crypt(plaintext[:ChunkSize])
		if err != nil {
			t.Fatalf("encrypt chunk %d: %s", i, err)
		}
		got, err := decrypter.Crypt(ciphertext)
		if err != nil {
			t.Fatalf("decrypt chunk %d: %s", i, err)
		}
		if !bytes.Equal(got, plaintext[:ChunkSize]) {
			t.Fatalf("chunk %d = %x, want %x", i, got, plaintext[:ChunkSize])
		}
	}
}

func TestFSChaCha20Poly1305RoundTripAcrossRekeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, KeySize)
	encrypter, err := NewFSChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 encrypter err: %s", err)
	}
	decrypter, err := NewFSChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 decrypter err: %s", err)
	}

	for i := uint64(0); i < 2*RekeyInterval+3; i++ {
		var plaintext [8]byte
		binary.LittleEndian.PutUint64(plaintext[:], i)
		aad := []byte{byte(i), byte(i >> 8)}
		ciphertext, err := encrypter.Encrypt(aad, plaintext[:])
		if err != nil {
			t.Fatalf("encrypt packet %d: %s", i, err)
		}
		got, err := decrypter.Decrypt(aad, ciphertext)
		if err != nil {
			t.Fatalf("decrypt packet %d: %s", i, err)
		}
		if !bytes.Equal(got, plaintext[:]) {
			t.Fatalf("packet %d = %x, want %x", i, got, plaintext)
		}
	}
}

func TestFailedAuthenticationConsumesNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	encrypter, err := NewFSChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 encrypter err: %s", err)
	}
	decrypter, err := NewFSChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 decrypter err: %s", err)
	}

	ciphertext, err := encrypter.Encrypt([]byte("aad"), []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt err: %s", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := decrypter.Decrypt([]byte("aad"), tampered); err == nil {
		t.Fatalf("Decrypt accepted a modified authentication tag")
	}

	if decrypter.packetCounter != 1 {
		t.Fatalf("packet counter after failed authentication = %d, want 1", decrypter.packetCounter)
	}

	nextCiphertext, err := encrypter.Encrypt([]byte("next aad"), []byte("next payload"))
	if err != nil {
		t.Fatalf("Encrypt next packet err: %s", err)
	}
	got, err := decrypter.Decrypt([]byte("next aad"), nextCiphertext)
	if err != nil {
		t.Fatalf("Decrypt next packet err: %s", err)
	}
	if string(got) != "next payload" {
		t.Fatalf("Decrypt = %q, want next payload", got)
	}
}

func TestCipherCountersRejectWraparound(t *testing.T) {
	stream, err := NewFSChaCha20(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("NewFSChaCha20 err: %s", err)
	}
	stream.chunkCounter = math.MaxUint64
	if _, err := stream.Crypt(make([]byte, ChunkSize)); err == nil {
		t.Fatalf("FSChaCha20 accepted an exhausted chunk counter")
	}

	aead, err := NewFSChaCha20Poly1305(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("NewFSChaCha20Poly1305 err: %s", err)
	}
	aead.packetCounter = math.MaxUint64
	if _, err := aead.Encrypt(nil, nil); err == nil {
		t.Fatalf("FSChaCha20Poly1305 accepted an exhausted packet counter")
	}
}

func TestNilCipherReceiversReturnErrors(t *testing.T) {
	var stream *FSChaCha20
	if _, err := stream.Crypt(make([]byte, ChunkSize)); err == nil {
		t.Fatalf("nil FSChaCha20 receiver did not return an error")
	}

	var aead *FSChaCha20Poly1305
	if _, err := aead.Encrypt(nil, nil); err == nil {
		t.Fatalf("nil FSChaCha20Poly1305 receiver did not return an error")
	}
}
