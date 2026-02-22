package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/slipe-fun/skid/pkg/identity"
)

const (
	nonceSize           = 12
	bundleHashSize      = 32
	identityHashSize    = 32
	oneTimeKeyIDSize    = 16
	expectedWrappedSize = 48
	maxCiphertextSize   = 1 << 20
)

func validateUserPublic(keys *identity.UserPublic) error {
	if err := validateUserPublicLongTerm(keys); err != nil {
		return err
	}
	return validateOneTimePublic(keys.OneTimeKeyID, keys.OneTimeKyberKey, keys.OneTimeECDHKey)
}

func validateUserPublicLongTerm(keys *identity.UserPublic) error {
	if len(keys.KyberKey) != kyber768.PublicKeySize {
		return fmt.Errorf("invalid kyber public key size: got %d, want %d", len(keys.KyberKey), kyber768.PublicKeySize)
	}
	if len(keys.ECDHKey) != x448.Size {
		return fmt.Errorf("invalid ecdh public key size: got %d, want %d", len(keys.ECDHKey), x448.Size)
	}
	if len(keys.Ed25519Key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key size: got %d, want %d", len(keys.Ed25519Key), ed25519.PublicKeySize)
	}
	return nil
}

func validateUserPrivate(keys *identity.UserPrivate) error {
	if err := validateUserPrivateLongTerm(keys); err != nil {
		return err
	}
	return validateOneTimePrivate(keys.OneTimeKeyID, keys.OneTimeKyberKey, keys.OneTimeECDHKey)
}

func validateUserPrivateLongTerm(keys *identity.UserPrivate) error {
	if len(keys.KyberKey) != kyber768.PrivateKeySize {
		return fmt.Errorf("invalid kyber private key size: got %d, want %d", len(keys.KyberKey), kyber768.PrivateKeySize)
	}
	if len(keys.ECDHKey) != x448.Size {
		return fmt.Errorf("invalid ecdh private key size: got %d, want %d", len(keys.ECDHKey), x448.Size)
	}
	if len(keys.Ed25519Key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key size: got %d, want %d", len(keys.Ed25519Key), ed25519.PrivateKeySize)
	}
	return nil
}

func validateOneTimePublic(keyID, kyberKey, ecdhKey []byte) error {
	if len(keyID) == 0 && len(kyberKey) == 0 && len(ecdhKey) == 0 {
		return nil
	}
	if len(keyID) != oneTimeKeyIDSize {
		return fmt.Errorf("invalid one-time key id size: got %d, want %d", len(keyID), oneTimeKeyIDSize)
	}
	if len(kyberKey) != kyber768.PublicKeySize {
		return fmt.Errorf("invalid one-time kyber public key size: got %d, want %d", len(kyberKey), kyber768.PublicKeySize)
	}
	if len(ecdhKey) != x448.Size {
		return fmt.Errorf("invalid one-time ecdh public key size: got %d, want %d", len(ecdhKey), x448.Size)
	}
	return nil
}

func validateOneTimePrivate(keyID, kyberKey, ecdhKey []byte) error {
	if len(keyID) == 0 && len(kyberKey) == 0 && len(ecdhKey) == 0 {
		return nil
	}
	if len(keyID) != oneTimeKeyIDSize {
		return fmt.Errorf("invalid one-time key id size: got %d, want %d", len(keyID), oneTimeKeyIDSize)
	}
	if len(kyberKey) != kyber768.PrivateKeySize {
		return fmt.Errorf("invalid one-time kyber private key size: got %d, want %d", len(kyberKey), kyber768.PrivateKeySize)
	}
	if len(ecdhKey) != x448.Size {
		return fmt.Errorf("invalid one-time ecdh private key size: got %d, want %d", len(ecdhKey), x448.Size)
	}
	return nil
}

func validateEncryptedMessage(m *EncryptedMessage) error {
	if len(m.MessageID) != oneTimeKeyIDSize {
		return fmt.Errorf("invalid message id size: got %d, want %d", len(m.MessageID), oneTimeKeyIDSize)
	}
	if len(m.ReceiverOneTimeKeyID) != oneTimeKeyIDSize {
		return fmt.Errorf("invalid receiver one-time key id size: got %d, want %d", len(m.ReceiverOneTimeKeyID), oneTimeKeyIDSize)
	}
	if len(m.Ciphertext) == 0 {
		return errors.New("empty ciphertext")
	}
	if len(m.Ciphertext) > maxCiphertextSize {
		return fmt.Errorf("ciphertext exceeds maximum size: got %d, max %d", len(m.Ciphertext), maxCiphertextSize)
	}
	if len(m.IV) != nonceSize {
		return fmt.Errorf("invalid message iv size: got %d, want %d", len(m.IV), nonceSize)
	}
	if len(m.EncapsulatedKey) != kyber768.CiphertextSize {
		return fmt.Errorf("invalid receiver encapsulated key size: got %d, want %d", len(m.EncapsulatedKey), kyber768.CiphertextSize)
	}
	if len(m.EncapsulatedKeySender) != kyber768.CiphertextSize {
		if len(m.EncapsulatedKeySender) != 0 {
			return fmt.Errorf("invalid sender encapsulated key size: got %d, want 0", len(m.EncapsulatedKeySender))
		}
	}
	if len(m.WrappedCekReceiver) != expectedWrappedSize {
		return errors.New("invalid wrapped receiver cek size")
	}
	if len(m.WrappedCekSender) != 0 {
		return errors.New("sender wrapped cek must be empty")
	}
	if len(m.WrapIVReceiver) != nonceSize {
		return errors.New("invalid wrap receiver iv size")
	}
	if len(m.WrapIVSender) != 0 {
		return errors.New("sender wrap iv must be empty")
	}
	if len(m.WrapSaltReceiver) != bundleHashSize {
		return errors.New("invalid wrap receiver salt size")
	}
	if len(m.WrapSaltSender) != 0 {
		return errors.New("sender wrap salt must be empty")
	}
	if len(m.SenderIdentityHash) != identityHashSize || len(m.ReceiverIdentityHash) != identityHashSize {
		return errors.New("invalid identity hash size")
	}
	if len(m.SenderBundleHash) != bundleHashSize || len(m.ReceiverBundleHash) != bundleHashSize {
		return errors.New("invalid bundle hash size")
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(m.Signature), ed25519.SignatureSize)
	}
	return nil
}
