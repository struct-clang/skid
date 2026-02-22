package crypto

import (
	"crypto/rand"
	"fmt"

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
	if len(pkBytes) != kyber768.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid kyber public key size: got %d, want %d", len(pkBytes), kyber768.PublicKeySize)
	}

	pk := new(kyber768.PublicKey)
	pk.Unpack(pkBytes)

	return kyber768.Scheme().Encapsulate(pk)
}

func DecapsulateKyber(skBytes, ct []byte) ([]byte, error) {
	if len(skBytes) != kyber768.PrivateKeySize {
		return nil, fmt.Errorf("invalid kyber private key size: got %d, want %d", len(skBytes), kyber768.PrivateKeySize)
	}
	if len(ct) != kyber768.CiphertextSize {
		return nil, fmt.Errorf("invalid kyber ciphertext size: got %d, want %d", len(ct), kyber768.CiphertextSize)
	}

	sk := new(kyber768.PrivateKey)
	sk.Unpack(skBytes)

	return kyber768.Scheme().Decapsulate(sk, ct)
}
