package main

import (
	"fmt"
	"skid/internal/crypto"
)

func main() {
	//kem

	kyberPublicKey, kyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		fmt.Println("error generating kyber keypair:", err)
		return
	}

	ct, ss, err := crypto.EncapsulateKyber(kyberPublicKey)
	if err != nil {
		fmt.Println("error encapsulating kyber key:", err)
		return
	}

	fmt.Printf("Kyber Public Key: %x\n", kyberPublicKey)
	fmt.Printf("Kyber Secret Key: %x\n", kyberSecretKey)
	fmt.Printf("Kyber Ciphertext: %x\n", ct)
	fmt.Printf("Kyber Shared Secret: %x\n", ss)

	decapsulatedSS, err := crypto.DecapsulateKyber(kyberSecretKey, ct)
	if err != nil {
		fmt.Println("error decapsulating kyber key:", err)
		return
	}

	fmt.Printf("Kyber Decapsulated Shared Secret: %x\n", decapsulatedSS)

	// ecdh

	alicePublicKey, aliceSecretKey := crypto.GenerateECDHKeyPair()
	bobPublicKey, bobSecretKey := crypto.GenerateECDHKeyPair()

	aliceSharedSecret := crypto.DeriveECDHSharedSecret(aliceSecretKey, bobPublicKey)
	bobSharedSecret := crypto.DeriveECDHSharedSecret(bobSecretKey, alicePublicKey)

	fmt.Printf("Alice Public Key: %x\n", alicePublicKey)
	fmt.Printf("Alice Secret Key: %x\n", aliceSecretKey)
	fmt.Printf("Bob Public Key: %x\n", bobPublicKey)
	fmt.Printf("Bob Secret Key: %x\n", bobSecretKey)
	fmt.Printf("Alice Shared Secret: %x\n", aliceSharedSecret)
	fmt.Printf("Bob Shared Secret: %x\n", bobSharedSecret)

	if string(aliceSharedSecret) == string(bobSharedSecret) {
		fmt.Println("ECDH shared secrets match.")
	} else {
		fmt.Println("ECDH shared secrets do not match.")
	}
}
