package protocol

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, receiverPublicKeys *identity.UserPublic, receiverPrivateKeys *identity.UserPrivate, senderPublicKeys *identity.UserPublic, isAuthor bool, expectedSenderIdentityHash []byte) ([]byte, error) {
	if encrypted == nil || receiverPublicKeys == nil || receiverPrivateKeys == nil || senderPublicKeys == nil {
		return nil, errors.New("nil input")
	}
	if err := validateEncryptedMessage(encrypted); err != nil {
		return nil, err
	}
	if err := validateUserPublicLongTerm(receiverPublicKeys); err != nil {
		return nil, fmt.Errorf("invalid receiver public keys: %w", err)
	}
	if err := validateUserPrivateLongTerm(receiverPrivateKeys); err != nil {
		return nil, fmt.Errorf("invalid receiver private keys: %w", err)
	}
	if err := validateUserPublicLongTerm(senderPublicKeys); err != nil {
		return nil, fmt.Errorf("invalid sender public keys: %w", err)
	}
	if len(expectedSenderIdentityHash) != identityHashSize {
		return nil, errors.New("expected sender identity hash must be 32 bytes")
	}
	if isAuthor {
		return nil, errors.New("author-side decryption is disabled for forward secrecy")
	}
	if !isAuthor {
		if err := validateOneTimePublic(receiverPublicKeys.OneTimeKeyID, receiverPublicKeys.OneTimeKyberKey, receiverPublicKeys.OneTimeECDHKey); err != nil {
			return nil, fmt.Errorf("invalid receiver one-time public keys: %w", err)
		}
		if err := validateOneTimePrivate(receiverPrivateKeys.OneTimeKeyID, receiverPrivateKeys.OneTimeKyberKey, receiverPrivateKeys.OneTimeECDHKey); err != nil {
			return nil, fmt.Errorf("invalid receiver one-time private keys: %w", err)
		}
	}

	senderBundleHash := identity.BundleHash(senderPublicKeys)
	if subtle.ConstantTimeCompare(senderBundleHash, encrypted.SenderBundleHash) != 1 {
		return nil, errors.New("sender bundle hash mismatch")
	}
	expectedSenderIdentity := identity.LongTermIdentityHash(senderPublicKeys)
	if subtle.ConstantTimeCompare(expectedSenderIdentityHash, expectedSenderIdentity) != 1 {
		return nil, errors.New("unexpected sender identity hash")
	}
	if subtle.ConstantTimeCompare(expectedSenderIdentity, encrypted.SenderIdentityHash) != 1 {
		return nil, errors.New("sender identity hash mismatch")
	}

	receiverBundleHash := identity.BundleHash(receiverPublicKeys)
	if subtle.ConstantTimeCompare(receiverBundleHash, encrypted.ReceiverBundleHash) != 1 {
		return nil, errors.New("receiver bundle hash mismatch")
	}
	receiverIdentityHash := identity.LongTermIdentityHash(receiverPublicKeys)
	if subtle.ConstantTimeCompare(receiverIdentityHash, encrypted.ReceiverIdentityHash) != 1 {
		return nil, errors.New("receiver identity hash mismatch")
	}

	signingPayload, err := signaturePayload(encrypted)
	if err != nil {
		return nil, fmt.Errorf("build signature payload: %w", err)
	}
	if !ed25519.Verify(senderPublicKeys.Ed25519Key, signingPayload, encrypted.Signature) {
		return nil, errors.New("invalid signature")
	}

	reservation, err := beginReplayReservation(receiverBundleHash, encrypted.MessageID, encrypted.CreatedAtUnix)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = reservation.Cancel()
		}
	}()

	var cek []byte

	if subtle.ConstantTimeCompare(receiverPublicKeys.OneTimeKeyID, encrypted.ReceiverOneTimeKeyID) != 1 {
		return nil, errors.New("receiver one-time key id mismatch")
	}

	ssReceiver, err := crypto.HybridDecrypt(
		senderPublicKeys.ECDHKey,
		receiverPrivateKeys.OneTimeECDHKey,
		receiverPrivateKeys.OneTimeKyberKey,
		encrypted.EncapsulatedKey,
	)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(ssReceiver)

	kekReceiver, err := crypto.DeriveAesKey(ssReceiver, encrypted.WrapSaltReceiver)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kekReceiver)

	cek, err = crypto.Decrypt(kekReceiver, encrypted.WrapIVReceiver, encrypted.WrappedCekReceiver)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(cek)

	plaintext, err := crypto.Decrypt(cek, encrypted.IV, encrypted.Ciphertext)
	if err != nil {
		return nil, err
	}

	if err := reservation.Commit(); err != nil {
		return nil, err
	}
	committed = true

	return plaintext, nil
}
