package main

import (
	"fmt"
	"skid/internal/crypto"
)

func main() {
	// mlkem768 keygen

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
}
