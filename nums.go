package nums

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
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

	// Create a SubjectPublicKeyInfo structure
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oidP256,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oidP256.String())},
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

func ParsePublicKey(der []byte, curve elliptic.Curve) (*PublicKey, error) {
	var publicKeyInfo struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		return nil, err
	}

	X, Y := elliptic.Unmarshal(curve, publicKeyInfo.PublicKey.Bytes)

	return &PublicKey{X: X, Y: Y}, nil
}

func (pk *PrivateKey) MarshalPKCS8PrivateKey(curve elliptic.Curve) ([]byte, error) {
	if !curve.IsOnCurve(pk.PublicKey.X, pk.PublicKey.Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Create a PrivateKeyInfo structure
	privateKeyInfo := struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PrivateKey          []byte
	}{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oidP256, 
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oidP256.String())},
		},
	}

	// Convert the private key D to bytes
	dBytes := pk.D.Bytes()

	curveSize := (curve.Params().BitSize + 7) / 8
	if len(dBytes) < curveSize {
		padding := make([]byte, curveSize-len(dBytes))
		dBytes = append(padding, dBytes...)
	}

	privateKeyInfo.PrivateKey = dBytes

	// Marshal the PrivateKeyInfo structure
	derBytes, err := asn1.Marshal(privateKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePrivateKey(der []byte, curve elliptic.Curve) (*PrivateKey, error) {
	var privateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PrivateKey          []byte
	}
	_, err := asn1.Unmarshal(der, &privateKeyInfo)
	if err != nil {
		return nil, err
	}

	X, Y := elliptic.Unmarshal(curve, privateKeyInfo.PrivateKey)

	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			X: X,
			Y: Y,
		},
		D: new(big.Int).SetBytes(privateKeyInfo.PrivateKey),
	}

	return privateKey, nil
}



// ToECDSA converts PublicKey to *ecdsa.PublicKey
func (pk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: P512(),
		X:     pk.X,
		Y:     pk.Y,
	}
}

func (pk *PrivateKey) ToECDSAPrivateKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: P512(),
			X:     pk.PublicKey.X,
			Y:     pk.PublicKey.Y,
		},
		D: pk.D,
	}
}

// Compute the shared key between two ECDSA keys
func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Compute shared key
	x, _ := P512().ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), nil
}