package bip324_crypto

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const EllswiftPubKeyLength = 64

var fieldPrime = new(big.Int).Set(secp.Params().P)

type EllswiftExchange struct {
	privKey        *secp.PrivateKey
	ellswiftPubKey [EllswiftPubKeyLength]byte
}

func NewEllswiftExchange() (*EllswiftExchange, error) {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	defer privKey.Zero()

	ellswiftPubKey, err := GetEllswiftPubKey(privKey.PubKey())
	if err != nil {
		privKey.Zero()
		return nil, err
	}

	return NewEllswiftExchangeFromKeys(privKey, ellswiftPubKey)
}

func NewEllswiftExchangeFromKeys(privKey *secp.PrivateKey, ourEllswiftPubKey []byte) (*EllswiftExchange, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if privKey.Key.IsZero() {
		return nil, fmt.Errorf("private key is zero")
	}
	if len(ourEllswiftPubKey) != EllswiftPubKeyLength {
		return nil, fmt.Errorf("ellswift public key is wrong length, got %d, want %d", len(ourEllswiftPubKey), EllswiftPubKeyLength)
	}

	decodedX, err := ellswiftDecodePubkey(ourEllswiftPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode ellswift public key: %w", err)
	}

	var expectedX secp.FieldVal
	expectedX.SetByteSlice(privKey.PubKey().X().Bytes())
	if !decodedX.Normalize().Equals(expectedX.Normalize()) {
		return nil, fmt.Errorf("ellswift public key does not encode the private key's public point")
	}

	serializedPrivateKey := privKey.Serialize()
	exchange := &EllswiftExchange{
		privKey: secp.PrivKeyFromBytes(serializedPrivateKey),
	}
	clear(serializedPrivateKey)
	copy(exchange.ellswiftPubKey[:], ourEllswiftPubKey)
	return exchange, nil
}

func (ex *EllswiftExchange) destroyPrivateKey() {
	if ex != nil && ex.privKey != nil {
		ex.privKey.Zero()
		ex.privKey = nil
	}
}

// ComputeSharedSecret performs the BIP324 tagged x-only ECDH calculation.
func (ex *EllswiftExchange) ComputeSharedSecret(otherEllswiftPubKey []byte, initiating bool) ([]byte, error) {
	if ex == nil || ex.privKey == nil {
		return nil, fmt.Errorf("ellswift exchange is not initialized")
	}

	theirs, err := parseEllswiftPubKey(otherEllswiftPubKey)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := ellswift.V2Ecdh(
		ex.privKey, theirs, ex.ellswiftPubKey, initiating,
	)
	if err != nil {
		return nil, err
	}

	result := append([]byte(nil), sharedSecret[:]...)
	clear(sharedSecret[:])
	return result, nil
}

// EllswiftEcdhXonly computes the x coordinate of the shared ECDH point.
func (ex *EllswiftExchange) EllswiftEcdhXonly(otherPubKeyEncoded []byte) ([]byte, error) {
	if ex == nil || ex.privKey == nil {
		return nil, fmt.Errorf("ellswift exchange is not initialized")
	}

	theirs, err := parseEllswiftPubKey(otherPubKeyEncoded)
	if err != nil {
		return nil, err
	}

	sharedX, err := ellswift.EllswiftECDHXOnly(theirs, ex.privKey)
	if err != nil {
		return nil, err
	}
	result := append([]byte(nil), sharedX[:]...)
	clear(sharedX[:])
	return result, nil
}

// GetEllswiftPubKey uniformly samples an ElligatorSwift encoding for pubKey.
func GetEllswiftPubKey(pubKey *secp.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	var x secp.FieldVal
	x.SetByteSlice(pubKey.X().Bytes())
	x.Normalize()

	for {
		uInt, err := crand.Int(crand.Reader, fieldPrime)
		if err != nil {
			return nil, err
		}
		if uInt.Sign() == 0 {
			continue
		}

		var u secp.FieldVal
		u.SetByteSlice(uInt.Bytes())

		var caseByte [1]byte
		if _, err := io.ReadFull(crand.Reader, caseByte[:]); err != nil {
			return nil, err
		}

		t := ellswift.XSwiftECInv(&u, &x, int(caseByte[0]&7))
		if t == nil {
			continue
		}

		uBytes := u.Normalize().Bytes()
		tBytes := t.Normalize().Bytes()
		encoded := make([]byte, EllswiftPubKeyLength)
		copy(encoded[:32], uBytes[:])
		copy(encoded[32:], tBytes[:])
		return encoded, nil
	}
}

// XSwiftECInv preserves the package's historical argument order (x, u, case).
func XSwiftECInv(x, u *secp.FieldVal, caseFlag int) *secp.FieldVal {
	if x == nil || u == nil || caseFlag < 0 || caseFlag > 7 {
		return nil
	}

	xCopy := *x
	uCopy := *u
	xCopy.Normalize()
	uCopy.Normalize()
	return ellswift.XSwiftECInv(&uCopy, &xCopy, caseFlag)
}

// XSwiftEC decodes an ElligatorSwift pair without mutating its inputs.
func XSwiftEC(u, t *secp.FieldVal) (*secp.FieldVal, error) {
	if u == nil || t == nil {
		return nil, fmt.Errorf("ellswift field element is nil")
	}

	uCopy := *u
	tCopy := *t
	uCopy.Normalize()
	tCopy.Normalize()
	return ellswift.XSwiftEC(&uCopy, &tCopy)
}

func ellswiftDecodePubkey(encoded []byte) (*secp.FieldVal, error) {
	ellswiftPubKey, err := parseEllswiftPubKey(encoded)
	if err != nil {
		return nil, err
	}

	var u, t secp.FieldVal
	u.SetByteSlice(ellswiftPubKey[:32])
	t.SetByteSlice(ellswiftPubKey[32:])
	return XSwiftEC(&u, &t)
}

func parseEllswiftPubKey(encoded []byte) ([EllswiftPubKeyLength]byte, error) {
	var result [EllswiftPubKeyLength]byte
	if len(encoded) != EllswiftPubKeyLength {
		return result, fmt.Errorf("ellswift public key is wrong length, got %d, want %d", len(encoded), EllswiftPubKeyLength)
	}
	copy(result[:], encoded)
	return result, nil
}

// TaggedHash computes a BIP340 tagged hash.
func TaggedHash(tag string, data []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(data)
	return h.Sum(nil)
}
