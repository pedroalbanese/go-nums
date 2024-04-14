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
    oidNumsp384d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 3}
    oidNumsp512d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 5}
)

var initonce sync.Once
var p256 *elliptic.CurveParams
var p512 *elliptic.CurveParams

func initP256() {
	p256 = new(elliptic.CurveParams)
	p256.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", 16)
	p256.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffe43c8275ea265c6020ab20294751a825", 16)
	p256.B, _ = new(big.Int).SetString("25581", 16)
	p256.Gx, _ = new(big.Int).SetString("01", 16)
	p256.Gy, _ = new(big.Int).SetString("696f1853c1e466d7fc82c96cceeedd6bd02c2f9375894ec10bf46306c2b56c77", 16)
	p256.BitSize = 256
}

func P256() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}

func initP512() {
	p512 = new(elliptic.CurveParams)
	p512.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", 16)
	p512.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b3ca4fb94e7831b4fc258ed97d0bdc63b568b36607cd243ce153f390433555d", 16)
	p512.B, _ = new(big.Int).SetString("1d99b", 16)
	p512.Gx, _ = new(big.Int).SetString("02", 16)
	p512.Gy, _ = new(big.Int).SetString("1c282eb23327f9711952c250ea61ad53fcc13031cf6dd336e0b9328433afbdd8cc5a1c1f0c716fdc724dde537c2b0adb00bb3d08dc83755b205cc30d7f83cf28", 16)
	p512.BitSize = 512
}

func P512() elliptic.Curve {
	initonce.Do(initP512)
	return p512
}

var oidP256 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 111}

// Define pkAlgorithmIdentifier to avoid undefined identifier
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type PublicKey struct {
	X, Y *big.Int
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
	case P256():
		oid = oidNumsp256d1
	case P512():
		oid = oidNumsp512d1
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

	// Determine the curve based on the OID
	var curve elliptic.Curve
	switch {
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp256d1):
		curve = P256()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidNumsp512d1):
		curve = P512()
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

	return &PublicKey{X: X, Y: Y}, nil
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
	case P256():
		oid = oidNumsp256d1
	case P512():
		oid = oidNumsp512d1
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
		curve = P256()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidNumsp512d1):
		curve = P512()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	X := privateKeyInfo.PublicKey.X
	Y := privateKeyInfo.PublicKey.Y
	D := new(big.Int).SetBytes(privateKeyInfo.PrivateKey)

	if !curve.IsOnCurve(X, Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Create and return the private key
	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			X: X,
			Y: Y,
		},
		D: D,
	}

	return privateKey, nil
}

func (pk *PublicKey) ToECDSA() (*ecdsa.PublicKey, error) {
	// Determine the curve based on the OID of the public key
	var curve elliptic.Curve
	switch {
	case pk.Curve.Equal(oidNumsp256d1):
		curve = P256()
	case pk.Curve.Equal(oidNumsp512d1):
		curve = P512()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	// Return the ECDSA public key
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     pk.X,
		Y:     pk.Y,
	}, nil
}

func (pk *PrivateKey) ToECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	// Determine the curve based on the OID of the private key
	var curve elliptic.Curve
	switch {
	case pk.Curve.Equal(oidNumsp256d1):
		curve = P256()
	case pk.Curve.Equal(oidNumsp512d1):
		curve = P512()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	// Create and return the ECDSA private key
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     pk.PublicKey.X,
			Y:     pk.PublicKey.Y,
		},
		D: pk.D,
	}, nil
}

func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Compute shared key
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), nil
}
