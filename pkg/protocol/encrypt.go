package protocol

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

type EncryptedMessage struct {
	MessageID            []byte
	CreatedAtUnix        int64
	ReceiverOneTimeKeyID []byte
	Ciphertext           []byte
	IV                   []byte
	EncapsulatedKey      []byte
	WrappedCekReceiver   []byte
	WrapIVReceiver       []byte
	WrapSaltReceiver     []byte

	EncapsulatedKeySender []byte
	WrappedCekSender      []byte
	WrapIVSender          []byte
	WrapSaltSender        []byte

	SenderIdentityHash   []byte
	ReceiverIdentityHash []byte
	SenderBundleHash     []byte
	ReceiverBundleHash   []byte
	Signature            []byte
}

func Encrypt(content string, senderPublicKeys *identity.UserPublic, senderPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic, expectedReceiverIdentityHash []byte) (*EncryptedMessage, error) {
	if senderPublicKeys == nil || senderPrivateKeys == nil || receiverPublicKeys == nil {
		return nil, errors.New("nil key bundle")
	}
	if err := validateUserPublicLongTerm(senderPublicKeys); err != nil {
		return nil, fmt.Errorf("invalid sender public keys: %w", err)
	}
	if err := validateUserPrivateLongTerm(senderPrivateKeys); err != nil {
		return nil, fmt.Errorf("invalid sender private keys: %w", err)
	}
	if err := validateUserPublic(receiverPublicKeys); err != nil {
		return nil, fmt.Errorf("invalid receiver public keys: %w", err)
	}

	derivedEdPublic := ed25519.PrivateKey(senderPrivateKeys.Ed25519Key).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(derivedEdPublic, senderPublicKeys.Ed25519Key) != 1 {
		return nil, errors.New("sender private/public ed25519 key mismatch")
	}
	if len(expectedReceiverIdentityHash) != 32 {
		return nil, errors.New("expected receiver identity hash must be 32 bytes")
	}
	actualReceiverIdentityHash := identity.LongTermIdentityHash(receiverPublicKeys)
	if subtle.ConstantTimeCompare(actualReceiverIdentityHash, expectedReceiverIdentityHash) != 1 {
		return nil, errors.New("receiver identity hash mismatch")
	}

	if len(receiverPublicKeys.OneTimeKeyID) == 0 || len(receiverPublicKeys.OneTimeKyberKey) == 0 || len(receiverPublicKeys.OneTimeECDHKey) == 0 {
		return nil, errors.New("receiver one-time prekey is required")
	}

	resRecv, err := crypto.HybridEncrypt(receiverPublicKeys.OneTimeECDHKey, receiverPublicKeys.OneTimeKyberKey, senderPrivateKeys.ECDHKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(resRecv.SessionKey)

	cekRaw, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(cekRaw)

	wrapSaltReceiver, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	kekReceiver, err := crypto.DeriveAesKey(resRecv.SessionKey, wrapSaltReceiver)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kekReceiver)

	wrapIvReceiver, wrappedCekReceiver, err := crypto.Encrypt(kekReceiver, cekRaw)
	if err != nil {
		return nil, err
	}

	iv, ciphertext, err := crypto.Encrypt(cekRaw, []byte(content))
	if err != nil {
		return nil, err
	}

	messageID, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}

	encrypted := &EncryptedMessage{
		MessageID:            messageID,
		CreatedAtUnix:        time.Now().Unix(),
		ReceiverOneTimeKeyID: append([]byte{}, receiverPublicKeys.OneTimeKeyID...),
		Ciphertext:           ciphertext,
		IV:                   iv,
		EncapsulatedKey:      resRecv.CipherText,
		WrappedCekReceiver:   wrappedCekReceiver,
		WrapIVReceiver:       wrapIvReceiver,
		WrapSaltReceiver:     wrapSaltReceiver,
		SenderIdentityHash:   identity.LongTermIdentityHash(senderPublicKeys),
		ReceiverIdentityHash: actualReceiverIdentityHash,
		SenderBundleHash:     identity.BundleHash(senderPublicKeys),
		ReceiverBundleHash:   identity.BundleHash(receiverPublicKeys),
	}

	signingPayload, err := signaturePayload(encrypted)
	if err != nil {
		return nil, fmt.Errorf("build signature payload: %w", err)
	}
	encrypted.Signature = ed25519.Sign(senderPrivateKeys.Ed25519Key, signingPayload)

	return encrypted, nil
}
