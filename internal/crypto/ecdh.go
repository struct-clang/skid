package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
)

func GenerateECDHKeyPair() ([]byte, []byte, error) {
	var pk, sk x448.Key

	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, nil, fmt.Errorf("read random for x448 secret key: %w", err)
	}
	x448.KeyGen(&pk, &sk)

	return pk[:], sk[:], nil
}

func DeriveECDHSharedSecret(sk, pk []byte) ([]byte, error) {
	if len(sk) != x448.Size {
		return nil, fmt.Errorf("invalid x448 secret key size: got %d, want %d", len(sk), x448.Size)
	}
	if len(pk) != x448.Size {
		return nil, fmt.Errorf("invalid x448 public key size: got %d, want %d", len(pk), x448.Size)
	}

	var shared, secret, public x448.Key
	copy(secret[:], sk)
	copy(public[:], pk)

	if ok := x448.Shared(&shared, &secret, &public); !ok {
		return nil, errors.New("invalid x448 public key (low-order point)")
	}

	return shared[:], nil
}
