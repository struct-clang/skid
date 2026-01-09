package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
)

func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}
