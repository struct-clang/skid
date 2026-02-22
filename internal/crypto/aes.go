package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"golang.org/x/crypto/hkdf"
)

const aesGCMSIVNonceSize = 12

func NewAes(key []byte) (*subtle.AESGCMSIV, error) {
	return subtle.NewAESGCMSIV(key)
}

func DeriveAesKey(sessionKey, salt []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sessionKey, salt, []byte("aes-key-derivation"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	aes, err := NewAes(key)
	if err != nil {
		return nil, nil, err
	}

	fullResult, err := aes.Encrypt(plaintext, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(fullResult) < aesGCMSIVNonceSize {
		return nil, nil, fmt.Errorf("ciphertext too short: %d", len(fullResult))
	}

	iv := fullResult[:aesGCMSIVNonceSize]
	ciphertext := fullResult[aesGCMSIVNonceSize:]
	return iv, ciphertext, nil
}

func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != aesGCMSIVNonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(iv), aesGCMSIVNonceSize)
	}

	aes, err := NewAes(key)
	if err != nil {
		return nil, err
	}

	fullCiphertext := append(append([]byte{}, iv...), ciphertext...)

	return aes.Decrypt(fullCiphertext, nil)
}
