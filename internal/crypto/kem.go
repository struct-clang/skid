package crypto

import (
	"crypto/rand"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func GenerateKyberKeyPair() ([]byte, []byte, error) {
	pk, sk, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, skBytes, nil
}

func EncapsulateKyber(pkBytes []byte) ([]byte, []byte, error) {
	pk := new(kyber768.PublicKey)
	pk.Unpack(pkBytes)

	return kyber768.Scheme().Encapsulate(pk)
}

func DecapsulateKyber(skBytes, ct []byte) ([]byte, error) {
	sk := new(kyber768.PrivateKey)
	sk.Unpack(skBytes)

	return kyber768.Scheme().Decapsulate(sk, ct)
}
