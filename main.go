package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func main() {
	// x448 keygen
	var x448PublicKey, x448SecretKey x448.Key

	_, _ = io.ReadFull(rand.Reader, x448SecretKey[:])
	x448.KeyGen(&x448PublicKey, &x448SecretKey)

	fmt.Println(hex.EncodeToString(x448PublicKey[:]), hex.EncodeToString(x448SecretKey[:]))

	// mlkem768 keygen

	kyberPublicKey, kyberSecretKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return
	}

	pkBytes, err := kyberPublicKey.MarshalBinary()
	if err != nil {
		return
	}

	skBytes, err := kyberSecretKey.MarshalBinary()
	if err != nil {
		return
	}

	fmt.Println(hex.EncodeToString(pkBytes), "\n\n\n\n", hex.EncodeToString(skBytes))
}
