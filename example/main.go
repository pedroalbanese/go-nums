package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/pedroalbanese/go-nums"
)

func main() {
	// Generate an ECDSA key pair using the NUMSP256t1 curve
	privateKey, err := ecdsa.GenerateKey(nums.P256t1(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating private key:", err)
	}

	// Create a P256 private key structure
	pk := &nums.PrivateKey{
		PublicKey: nums.PublicKey{
			X: privateKey.PublicKey.X,
			Y: privateKey.PublicKey.Y,
		},
		D: privateKey.D,
	}

	// Marshal the private key to PKCS#8 format
	privateKeyBytes, err := pk.MarshalPKCS8PrivateKey(nums.P256t1())
	if err != nil {
		log.Fatal("Error marshaling private key to PKCS#8 format:", err)
	}

	// Marshal the public key to PKCS#8 format
	publicKeyBytes, err := pk.PublicKey.MarshalPKCS8PublicKey(nums.P256t1())
	if err != nil {
		log.Fatal("Error marshaling public key to PKCS#8 format:", err)
	}

	// Convert the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	// Convert the public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	// Print the PEM encoded keys
	fmt.Println("Private Key (PEM):")
	fmt.Println(string(privateKeyPEM))
	fmt.Println("Public Key (PEM):")
	fmt.Println(string(publicKeyPEM))

	// Digital Signature

	// Get keys from PEM blocks
	privateKeyFromPEM, err := func(data []byte) (*nums.PrivateKey, error) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("Error decoding PEM block of private key")
		}
		return nums.ParsePrivateKey(block.Bytes)
	}(privateKeyPEM)
	if err != nil {
		log.Fatal("Error getting private key from PEM block:", err)
	}

	publicKeyFromPEM, err := func(data []byte) (*nums.PublicKey, error) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("Error decoding PEM block of public key")
		}
		return nums.ParsePublicKey(block.Bytes)
	}(publicKeyPEM)
	if err != nil {
		log.Fatal("Error getting public key from PEM block:", err)
	}

	// Hash of the message
	hash := sha256.Sum256([]byte("message"))

	// Sign the message using the private key
	signature, err := ecdsa.SignASN1(rand.Reader, privateKeyFromPEM.ToECDSAPrivateKey(), hash[:])
	if err != nil {
		log.Fatal("Failed to sign the message:", err)
	}

	// Verify the signature using the public key
	valid := ecdsa.VerifyASN1(publicKeyFromPEM.ToECDSA(), hash[:], signature)
	if valid {
		fmt.Println("Valid signature")
	} else {
		fmt.Println("Invalid signature")
	}

	// ECDH

	// Generate an ECDSA key pair using the P256 curve
	privateKeyAlice, err := ecdsa.GenerateKey(nums.P256t1(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating private key for Alice:", err)
	}

	// Generate an ECDSA key pair using the P256 curve
	privateKeyBob, err := ecdsa.GenerateKey(nums.P256t1(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating private key for Bob:", err)
	}

	// Alice's public key
	publicKeyAlice := privateKeyAlice.PublicKey

	// Bob's public key
	publicKeyBob := privateKeyBob.PublicKey

	// Alice computes shared key
	sharedKeyAlice, err := nums.ECDH(privateKeyAlice, &publicKeyBob)
	if err != nil {
		log.Fatal("Error computing shared key for Alice:", err)
	}

	// Bob computes shared key
	sharedKeyBob, err := nums.ECDH(privateKeyBob, &publicKeyAlice)
	if err != nil {
		log.Fatal("Error computing shared key for Bob:", err)
	}

	fmt.Printf("Shared Key Alice : %x\n", sharedKeyAlice)
	fmt.Printf("Shared Key Bob   : %x\n", sharedKeyBob)
}
