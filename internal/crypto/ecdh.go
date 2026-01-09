package crypto

import (
	"crypto/rand"
	"io"

	"github.com/cloudflare/circl/dh/x448"
)

func GenerateECDHKeyPair() ([]byte, []byte) {
	var pk, sk x448.Key

	_, _ = io.ReadFull(rand.Reader, sk[:])
	x448.KeyGen(&pk, &sk)

	return pk[:], sk[:]
}

func DeriveECDHSharedSecret(sk, pk []byte) []byte {
	var shared, secret, public x448.Key
	copy(secret[:], sk)
	copy(public[:], pk)

	x448.Shared(&shared, &secret, &public)

	return shared[:]
}
