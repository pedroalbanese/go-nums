package nums

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
	"sync"
)

var (
	oidNums = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0}

	oidNumsp256d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 1}
	oidNumsp256t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 2}
	oidNumsp384d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 3}
	oidNumsp384t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 4}
	oidNumsp512d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 5}
	oidNumsp512t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 6}
)

var initonce sync.Once
var p256d1, p384d1, p512d1 *elliptic.CurveParams
var p256t1, p384t1, p512t1 *rcurve

func init() {
	initP256d1()
	initP384d1()
	initP512d1()

	initP256t1()
	initP384t1()
	initP512t1()
}

func initP256d1() {
	p256d1 = new(elliptic.CurveParams)
	p256d1.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", 16)
	p256d1.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffe43c8275ea265c6020ab20294751a825", 16)
	p256d1.B, _ = new(big.Int).SetString("25581", 16)
	p256d1.Gx, _ = new(big.Int).SetString("01", 16)
	p256d1.Gy, _ = new(big.Int).SetString("696f1853c1e466d7fc82c96cceeedd6bd02c2f9375894ec10bf46306c2b56c77", 16)
	p256d1.BitSize = 256
	p256d1.Name = "numsp256d1"
}

func P256d1() elliptic.Curve {
	initonce.Do(initP256d1)
	return p256d1
}

func initP384d1() {
	p384d1 = new(elliptic.CurveParams)
	p384d1.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3", 16)
	p384d1.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffd61eaf1eeb5d6881beda9d3d4c37e27a604d81f67b0e61b9", 16)
	p384d1.B, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff77bb", 16)
	p384d1.Gx, _ = new(big.Int).SetString("02", 16)
	p384d1.Gy, _ = new(big.Int).SetString("3c9f82cb4b87b4dc71e763e0663e5dbd8034ed422f04f82673330dc58d15ffa2b4a3d0bad5d30f865bcbbf503ea66f43", 16)
	p384d1.BitSize = 384
	p384d1.Name = "numsp384d1"
}

func P384d1() elliptic.Curve {
	initonce.Do(initP384d1)
	return p384d1
}

func initP512d1() {
	p512d1 = new(elliptic.CurveParams)
	p512d1.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", 16)
	p512d1.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b3ca4fb94e7831b4fc258ed97d0bdc63b568b36607cd243ce153f390433555d", 16)
	p512d1.B, _ = new(big.Int).SetString("1d99b", 16)
	p512d1.Gx, _ = new(big.Int).SetString("02", 16)
	p512d1.Gy, _ = new(big.Int).SetString("1c282eb23327f9711952c250ea61ad53fcc13031cf6dd336e0b9328433afbdd8cc5a1c1f0c716fdc724dde537c2b0adb00bb3d08dc83755b205cc30d7f83cf28", 16)
	p512d1.BitSize = 512
	p512d1.Name = "numsp512d1"
}

func P512d1() elliptic.Curve {
	initonce.Do(initP512d1)
	return p512d1
}

func initP256t1() {
	twisted := P256d1().Params()
	params := &elliptic.CurveParams{
		Name:    "numsp256t1",
		P:       new(big.Int).Set(twisted.P),
		N:       new(big.Int).Set(twisted.N),
		BitSize: twisted.BitSize,
	}
	params.Gx, _ = new(big.Int).SetString("0D", 16)
	params.Gy, _ = new(big.Int).SetString("7d0ab41e2a1276dba3d330b39fa046bfbe2a6d63824d303f707f6fb5331cadba", 16)
	r, _ := new(big.Int).SetString("3fffffffffffffffffffffffffffffffbe6aa55ad0a6bc64e5b84e6f1122b4ad", 16)
	p256t1 = newRcurve(P256d1(), params, r)
}

func P256t1() elliptic.Curve {
	initonce.Do(initP256t1)
	return p256t1
}

func initP384t1() {
	twisted := P384d1().Params()
	params := &elliptic.CurveParams{
		Name:    "numsp384t1",
		P:       new(big.Int).Set(twisted.P),
		N:       new(big.Int).Set(twisted.N),
		BitSize: twisted.BitSize,
	}
	params.Gx, _ = new(big.Int).SetString("08", 16)
	params.Gy, _ = new(big.Int).SetString("749cdaba136ce9b65bd4471794aa619daa5c7b4c930bff8ebd798a8ae753c6d72f003860febabad534a4acf5fa7f5bee", 16)
	r, _ := new(big.Int).SetString("3fffffffffffffffffffffffffffffffffffffffffffffffecd7d11ed5a259a25a13a0458e39f4e451d6d71f70426e25", 16)
	p384t1 = newRcurve(P384d1(), params, r)
}

func P384t1() elliptic.Curve {
	initonce.Do(initP384t1)
	return p384t1
}

func initP512t1() {
	twisted := P512d1().Params()
	params := &elliptic.CurveParams{
		Name:    "numsp512t1",
		P:       new(big.Int).Set(twisted.P),
		N:       new(big.Int).Set(twisted.N),
		BitSize: twisted.BitSize,
	}
	params.Gx, _ = new(big.Int).SetString("20", 16)
	params.Gy, _ = new(big.Int).SetString("7d67e841dc4c467b605091d80869212f9ceb124bf726973f9ff048779e1d614e62ae2ece5057b5dad96b7a897c1d72799261134638750f4f0cb91027543b1c5e", 16)
	r, _ := new(big.Int).SetString("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7e50809efdabbb9a624784f449545f0dcea5ff0cb800f894e78d1cb0b5f0189", 16)
	p512t1 = newRcurve(P512d1(), params, r)
}

func P512t1() elliptic.Curve {
	initonce.Do(initP512t1)
	return p512t1
}

// Define pkAlgorithmIdentifier to avoid undefined identifier
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type PublicKey struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

type PrivateKey struct {
	PublicKey PublicKey
	D         *big.Int
}

func (pk *PublicKey) MarshalPKCS8PublicKey(curve elliptic.Curve) ([]byte, error) {
	// Marshal the public key coordinates
	derBytes := elliptic.Marshal(curve, pk.X, pk.Y)

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256d1():
		oid = oidNumsp256d1
	case P384d1():
		oid = oidNumsp384d1
	case P512d1():
		oid = oidNumsp512d1
	case P256t1():
		oid = oidNumsp256t1
	case P384t1():
		oid = oidNumsp384t1
	case P512t1():
		oid = oidNumsp512t1
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a SubjectPublicKeyInfo structure
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: asn1.BitString{Bytes: derBytes, BitLength: len(derBytes) * 8},
	}

	// Marshal the SubjectPublicKeyInfo structure
	derBytes, err := asn1.Marshal(subjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePublicKey(der []byte) (*PublicKey, error) {
	var publicKeyInfo struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch {
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp256d1):
		curve = P256d1()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp384d1):
		curve = P384d1()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp512d1):
		curve = P512d1()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp256t1):
		curve = P256t1()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp384t1):
		curve = P384t1()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp512t1):
		curve = P512t1()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	// Check if the public key bytes are empty
	if len(publicKeyInfo.PublicKey.Bytes) == 0 {
		return nil, errors.New("public key bytes are empty")
	}

	// Unmarshal the public key coordinates
	X, Y := elliptic.Unmarshal(curve, publicKeyInfo.PublicKey.Bytes)
	if X == nil || Y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}

	// Return the parsed public key with the determined curve
	return &PublicKey{X: X, Y: Y, Curve: curve}, nil
}

func (pk *PrivateKey) MarshalPKCS8PrivateKey(curve elliptic.Curve) ([]byte, error) {
	if !curve.IsOnCurve(pk.PublicKey.X, pk.PublicKey.Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Convert the private key D to bytes
	dBytes := pk.D.Bytes()

	curveSize := (curve.Params().BitSize + 7) / 8
	if len(dBytes) < curveSize {
		padding := make([]byte, curveSize-len(dBytes))
		dBytes = append(padding, dBytes...)
	}

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256d1():
		oid = oidNumsp256d1
	case P384d1():
		oid = oidNumsp384d1
	case P512d1():
		oid = oidNumsp512d1
	case P256t1():
		oid = oidNumsp256t1
	case P384t1():
		oid = oidNumsp384t1
	case P512t1():
		oid = oidNumsp512t1
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a PrivateKeyInfo structure
	privateKeyInfo := struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: struct {
			X *big.Int
			Y *big.Int
		}{
			X: new(big.Int).SetBytes(pk.PublicKey.X.Bytes()),
			Y: new(big.Int).SetBytes(pk.PublicKey.Y.Bytes()),
		},
		PrivateKey: dBytes,
	}

	// Marshal the PrivateKeyInfo structure
	derBytes, err := asn1.Marshal(privateKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePrivateKey(der []byte) (*PrivateKey, error) {
	var privateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}
	_, err := asn1.Unmarshal(der, &privateKeyInfo)
	if err != nil {
		return nil, err
	}

	// Determine the curve based on the OID
	var curve elliptic.Curve
	switch {
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp256d1):
		curve = P256d1()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp384d1):
		curve = P384d1()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp512d1):
		curve = P512d1()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp256t1):
		curve = P256t1()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp384t1):
		curve = P384t1()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp512t1):
		curve = P512t1()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	X := privateKeyInfo.PublicKey.X
	Y := privateKeyInfo.PublicKey.Y
	D := new(big.Int).SetBytes(privateKeyInfo.PrivateKey)

	if !curve.IsOnCurve(X, Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Create and return the private key with the determined curve
	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			X:     X,
			Y:     Y,
			Curve: curve,
		},
		D: D,
	}

	return privateKey, nil
}

func (pk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}
}

func (pk *PrivateKey) ToECDSAPrivateKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: pk.PublicKey.Curve,
			X:     pk.PublicKey.X,
			Y:     pk.PublicKey.Y,
		},
		D: pk.D,
	}
}

func NewPrivateKey(privateKey *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: privateKey.PublicKey.Curve,
			X:     privateKey.PublicKey.X,
			Y:     privateKey.PublicKey.Y,
		},
		D: privateKey.D,
	}
}

func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Compute shared key
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), nil
}
