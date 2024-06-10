package bip324_crypto

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	EllswiftPubKeyLength = 64
)

var (
	feSize, _ = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)

	twoInv         = new(secp.FieldVal).SetInt(2).Inverse()
	minusThreeSqrt = new(secp.FieldVal).SetInt(3).Negate(1)
	_              = minusThreeSqrt.SquareRootVal(minusThreeSqrt)
)

type EllswiftExchange struct {
	PrivateKey     *secp.PrivateKey
	EllswiftPubKey []byte
}

func NewEllswiftExchange() (*EllswiftExchange, error) {
	pk, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return NewEllswiftExchangeFromKeys(pk, GetEllswiftPubKey(pk.PubKey()))
}

func NewEllswiftExchangeFromKeys(privKey *secp.PrivateKey, ourEllswiftPubKey []byte) (*EllswiftExchange, error) {
	return &EllswiftExchange{
		PrivateKey:     privKey,
		EllswiftPubKey: ourEllswiftPubKey,
	}, nil
}

// bip324_ellswift_xonly_ecdh returns shared secret - bip324_ellswift_xonly_ecdh
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L589
func (ex *EllswiftExchange) ComputeSharedSecret(otherEllswiftPubKey []byte, initiating bool) ([]byte, error) {
	ecdhPointX32, err := ex.EllswiftEcdhXonly(otherEllswiftPubKey)
	if err != nil {
		return nil, err
	}
	var h []byte
	if initiating {
		h = append(h, ex.EllswiftPubKey...)
		h = append(h, otherEllswiftPubKey...)
	} else {
		h = append(h, otherEllswiftPubKey...)
		h = append(h, ex.EllswiftPubKey...)
	}
	h = append(h, ecdhPointX32...)

	return TaggedHash("bip324_ellswift_xonly_ecdh", h), nil
}

// Compute X coordinate of shared ECDH point between elswift pubkey and privkey
// ellswift_ecdh_xonly
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L393
func (ex *EllswiftExchange) EllswiftEcdhXonly(otherPubKeyEncoded []byte) ([]byte, error) {
	otherPubKeyDecoded, err := ellswiftDecodePubkey(otherPubKeyEncoded)
	if err != nil {
		return nil, err
	}

	fvY := liftX(otherPubKeyDecoded)

	pubKey := secp.NewPublicKey(otherPubKeyDecoded, fvY)
	return secp.GenerateSharedSecret(ex.PrivateKey, pubKey), nil
}

func GetEllswiftPubKey(pubKey *secp.PublicKey) []byte {
	var x secp.FieldVal
	x.SetByteSlice(pubKey.X().Bytes())

	u, t := xelligatorswift(&x)
	uPlusT := bigInttoBytesLittleEndian(u)
	uPlusT = append(uPlusT, bigInttoBytesLittleEndian(t)...)
	return uPlusT
}

// isValidX checks if x is a valid x coordinate on the secp256k1 curve
// GE.is_valid()
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L308
func isValidX(x *secp.FieldVal) bool {
	var xCubed secp.FieldVal
	xCubed.Set(x).Square().Mul(x)

	var rhs secp.FieldVal
	rhs.Set(&xCubed).AddInt(7)

	return hasSquareRoot(&rhs)
}

func hasSquareRoot(val *secp.FieldVal) bool {
	var y, rhs2 secp.FieldVal
	rhs2.Set(val)
	y.Set(&rhs2).SquareRootVal(&rhs2)

	var y2, ySquared secp.FieldVal
	y2.Set(&y)
	ySquared.Set(&y2).Square()

	return ySquared.Equals(val)
}

// Given x and u, find t such that XSwiftEC(u, t) = x, or return
// xswiftec_inv
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L344C5-L344C17
func XSwiftECInv(x *secp.FieldVal, u *secp.FieldVal, caseFlag int) *secp.FieldVal {
	var v, s, uNeg secp.FieldVal
	uNeg.Set(u).Negate(1)

	if caseFlag&2 == 0 {
		// s = -(u**3 + 7) / (u**2 + u*v + v**2)

		var t secp.FieldVal
		t.Set(x).Negate(1).Add(&uNeg)
		if isValidX(&t) {
			return nil
		}
		v.Set(x)

		var p2, p3, u3 secp.FieldVal
		p2.Set(u).Mul(&v)
		p3.Set(&v).Mul(&v)
		u3.Set(u).Square().Mul(u)

		var part1, part2 secp.FieldVal
		part1.Set(&u3).AddInt(7).Normalize().Negate(1)
		part2.Set(u).Mul(u).Add(&p2).Add(&p3).Inverse()
		s.Set(&part1).Mul(&part2)
	} else {
		// s = x - u
		s.Set(x).Add(&uNeg).Normalize()
		if s.IsZero() {
			return nil
		}

		// r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()

		// 4 * (u**3 + 7)
		var u2, u3, part1, part2 secp.FieldVal
		u2.Set(u).Square()
		u3.Set(&u2).Mul(u)

		part1.Set(&u3).AddInt(7).MulInt(4)

		// 3 * s * u**2)
		part2.Set(&u2).Mul(&s).Mul(new(secp.FieldVal).SetInt(3))

		var sNeg, r secp.FieldVal
		sNeg.Set(&s).Negate(1)

		r.Set(&sNeg).Mul(part1.Add(&part2))

		if !hasSquareRoot(&r) {
			return nil
		}

		r.SquareRootVal(&r)
		if caseFlag&1 != 0 && r.IsZero() {
			return nil
		}

		// v = (-u + r / s) / 2

		var sInv secp.FieldVal
		sInv.Set(&s).Inverse()

		v.Set(&uNeg).Add(r.Mul(&sInv)).Mul(twoInv)
	}

	if !hasSquareRoot(&s) {
		return nil
	}

	var w, wNeg secp.FieldVal
	w.Set(&s).SquareRootVal(&s)
	wNeg.Set(&w).Negate(1)

	var res secp.FieldVal
	one := new(secp.FieldVal).SetInt(1)

	if caseFlag&5 == 0 {
		//return -w * (u * (1 - MINUS_3_SQRT) / 2 + v)

		var m, p1 secp.FieldVal
		m.Set(minusThreeSqrt).Negate(1)
		p1.Set(u).Mul(one.Add(&m))
		p1.Mul(twoInv).Add(&v)
		res.Set(&wNeg).Mul(&p1)

		return &res
	}

	if caseFlag&5 == 1 {
		//return w * (u * (1 + MINUS_3_SQRT) / 2 + v)

		var m, p1 secp.FieldVal
		m.Set(minusThreeSqrt)
		p1.Set(u).Mul(one.Add(&m)).Mul(twoInv).Add(&v)
		res.Set(&w).Mul(&p1)

		return &res
	}

	if caseFlag&5 == 4 {
		//return w * (u * (1 - MINUS_3_SQRT) / 2 + v)

		var m, p1 secp.FieldVal
		m.Set(minusThreeSqrt).Negate(1)
		p1.Set(u).Mul(one.Add(&m)).Mul(twoInv).Add(&v)
		res.Set(&w).Mul(&p1)
		return &res
	}

	if caseFlag&5 == 5 {
		//return -w * (u * (1 + MINUS_3_SQRT) / 2 + v)

		var m, p1 secp.FieldVal
		m.Set(minusThreeSqrt)
		p1.Set(u).Mul(one.Add(&m)).Mul(twoInv).Add(&v)
		res.Set(&wNeg).Mul(&p1)
		return &res
	}

	return nil
}

// """Given a field element X on the curve, find (u, t) that encode them."""
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L372
func xelligatorswift(x *secp.FieldVal) (*secp.FieldVal, *secp.FieldVal) {
	var u secp.FieldVal

	for {
		uInt, err := crand.Int(crand.Reader, feSize)
		if err != nil {
			panic(err)
		}
		u.SetByteSlice(uInt.Bytes())

		caseFlag := rand.Intn(8)
		t := XSwiftECInv(x, &u, caseFlag)
		if t != nil {
			return &u, t
		}
	}
}

func bigInttoBytesLittleEndian(bigInt *secp.FieldVal) []byte {
	bytesLittleEndian := bigInt.Bytes()
	bytesBigEndian := make([]byte, 32)
	copy(bytesBigEndian, bytesLittleEndian[:32])
	//for i := 0; i < len(bytesLittleEndian); i++ {
	//	bytesBigEndian[i] = bytesLittleEndian[i]
	//}

	return bytesBigEndian
}

// Return group element with specified field element as x coordinate (and even y)
func liftX(x *secp.FieldVal) *secp.FieldVal {
	var xCubed secp.FieldVal
	xCubed.Set(x).Square().Mul(x)

	var rhs secp.FieldVal
	rhs.Set(&xCubed).AddInt(7).Normalize()

	var y secp.FieldVal

	y.Set(&rhs).SquareRootVal(&rhs)

	y.Normalize()

	if y.IsOdd() {
		y.Normalize()
		y.Negate(1)
	}
	return &y
}

// Convert ellswift encoded X coordinate to 32-byte xonly format
// ellswift_decode
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L387
func ellswiftDecodePubkey(otherPubKey []byte) (*secp.FieldVal, error) {
	if len(otherPubKey) != EllswiftPubKeyLength {
		return nil, fmt.Errorf("otherPubKey is wrong length, got: %d, want: %d", len(otherPubKey), EllswiftPubKeyLength)
	}

	var u, t secp.FieldVal
	u.SetByteSlice(otherPubKey[:32])
	t.SetByteSlice(otherPubKey[32:])

	return XSwiftEC(&u, &t)
}

// Compute BIP-340 tagged hash with specified tag string of data
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L10
func TaggedHash(tag string, data []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	doubleTagHash := append(tagHash[:], tagHash[:]...)
	combinedData := append(doubleTagHash[:], data...)
	return sha256.Sum256(combinedData)
}

// Decode field elements (u, t) to an X coordinate on the curve
// xswiftec
// https://github.com/bitcoin/bips/blob/758a58ab54fddce0c6d062ed8fdf2b28c2eb7790/bip-0324/reference.py#L329
func XSwiftEC(u, t *secp.FieldVal) (*secp.FieldVal, error) {
	if u.Normalize().IsZero() {
		u = u.SetInt(1)
	}
	if t.Normalize().IsZero() {
		t = t.SetInt(1)
	}

	//  u^3 + t^2 + 7
	var u3, tSquared, sum, negU secp.FieldVal
	u3.Set(u).Square().Mul(u) // u^3
	tSquared.Set(t).Square()  // t^2
	sum.Set(&u3).Add(&tSquared).AddInt(7)

	// Handle the case where u^3 + t^2 + 7 == 0
	if sum.Normalize().IsZero() {
		t.MulInt(2)
		tSquared.Set(t).Square()
	}

	negU.Set(u).Normalize().Negate(1)

	//  x = (u^3 + 7 - t^2) / (2 * t)
	var X, twoTinv secp.FieldVal
	twoTinv.Set(t).Add(t).Inverse() // Inverse of 2 * t
	X.Set(&u3).AddInt(7).Add(tSquared.Normalize().Negate(1))
	X.Mul(&twoTinv)

	minus3SqrtUInv := new(secp.FieldVal).Set(u).Mul(minusThreeSqrt).Inverse()

	// Y = (X + t) / (MINUS_3_SQRT * u)
	var Y secp.FieldVal
	Y.Set(&X).Add(t).Mul(minus3SqrtUInv)

	/*
		three candidates:

			u + 4 * Y**2
			(-X / Y - u) / 2
			(X / Y - u) / 2
	*/
	var c1, c2, c3 secp.FieldVal

	var y2, y2Times4 secp.FieldVal
	y2.Set(&Y).Mul(&Y)
	y2Times4.Set(&y2).MulInt(4)
	c1.Set(u).Add(&y2Times4)
	if isValidX(&c1) {
		return &c1, nil
	}

	c2.Set(&X).Negate(1).Mul(new(secp.FieldVal).Set(&Y).Inverse()).Add(&negU).Mul(new(secp.FieldVal).SetInt(2).Inverse())
	if isValidX(&c2) {
		return &c2, nil
	}

	c3.Set(&X).Mul(new(secp.FieldVal).Set(&Y).Inverse()).Add(&negU).Mul(new(secp.FieldVal).SetInt(2).Inverse())
	if isValidX(&c3) {
		return &c3, nil
	}

	return nil, fmt.Errorf("no valid X found")
}
