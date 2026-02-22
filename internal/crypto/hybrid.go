package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type HybridResult struct {
	SessionKey []byte
	CipherText []byte
}

func HybridEncrypt(receiverECDHPublic, receiverKyberPublic, senderECDHPrivate []byte) (*HybridResult, error) {
	ECDHSS, err := DeriveECDHSharedSecret(senderECDHPrivate, receiverECDHPublic)
	if err != nil {
		return nil, err
	}
	defer Wipe(ECDHSS)

	kyberCT, kyberSS, err := EncapsulateKyber(receiverKyberPublic)
	if err != nil {
		return nil, err
	}
	defer Wipe(kyberSS)

	inputKeyMaterial := make([]byte, 0, len(kyberSS)+len(ECDHSS))
	inputKeyMaterial = append(inputKeyMaterial, kyberSS...)
	inputKeyMaterial = append(inputKeyMaterial, ECDHSS...)
	defer Wipe(inputKeyMaterial)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, []byte("skid-hybrid-session-key-v1"))

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return &HybridResult{
		SessionKey: sessionKey,
		CipherText: kyberCT,
	}, nil
}

func HybridDecrypt(senderECDHPublic, receiverECDHPrivate, receiverKyberPrivate, kyberCT []byte) ([]byte, error) {
	ECDHSS, err := DeriveECDHSharedSecret(receiverECDHPrivate, senderECDHPublic)
	if err != nil {
		return nil, err
	}
	defer Wipe(ECDHSS)

	kyberSS, err := DecapsulateKyber(receiverKyberPrivate, kyberCT)
	if err != nil {
		return nil, err
	}
	defer Wipe(kyberSS)

	inputKeyMaterial := make([]byte, 0, len(kyberSS)+len(ECDHSS))
	inputKeyMaterial = append(inputKeyMaterial, kyberSS...)
	inputKeyMaterial = append(inputKeyMaterial, ECDHSS...)
	defer Wipe(inputKeyMaterial)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, []byte("skid-hybrid-session-key-v1"))

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return sessionKey, nil
}
