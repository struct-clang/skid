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
	ECDHSS := DeriveECDHSharedSecret(senderECDHPrivate, receiverECDHPublic)
	kyberCT, kyberSS, err := EncapsulateKyber(receiverKyberPublic)
	if err != nil {
		return nil, err
	}

	inputKeyMaterial := append(kyberSS, ECDHSS...)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, nil)

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
	ECDHSS := DeriveECDHSharedSecret(receiverECDHPrivate, senderECDHPublic)

	kyberSS, err := DecapsulateKyber(receiverKyberPrivate, kyberCT)
	if err != nil {
		return nil, err
	}

	inputKeyMaterial := append(kyberSS, ECDHSS...)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, nil)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return sessionKey, nil
}
