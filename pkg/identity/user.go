package identity

import (
	"crypto/sha256"

	"github.com/slipe-fun/skid/internal/crypto"
)

type UserPrivate struct {
	KyberKey   []byte
	ECDHKey    []byte
	Ed25519Key []byte

	OneTimeKeyID    []byte
	OneTimeKyberKey []byte
	OneTimeECDHKey  []byte
}

type UserPublic struct {
	KyberKey   []byte
	ECDHKey    []byte
	Ed25519Key []byte

	OneTimeKeyID    []byte
	OneTimeKyberKey []byte
	OneTimeECDHKey  []byte
}

func NewUser() (*UserPrivate, *UserPublic, error) {
	kyberPublicKey, kyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ecdhPublicKey, ecdhSecretKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ed25519PublicKey, ed25519SecretKey, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	oneTimeKyberPublicKey, oneTimeKyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, nil, err
	}

	oneTimeECDHPublicKey, oneTimeECDHSecretKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	oneTimeKeyID, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, nil, err
	}

	public := &UserPublic{
		KyberKey:        kyberPublicKey,
		ECDHKey:         ecdhPublicKey,
		Ed25519Key:      ed25519PublicKey,
		OneTimeKeyID:    oneTimeKeyID,
		OneTimeKyberKey: oneTimeKyberPublicKey,
		OneTimeECDHKey:  oneTimeECDHPublicKey,
	}

	private := &UserPrivate{
		KyberKey:        kyberSecretKey,
		ECDHKey:         ecdhSecretKey,
		Ed25519Key:      ed25519SecretKey,
		OneTimeKeyID:    oneTimeKeyID,
		OneTimeKyberKey: oneTimeKyberSecretKey,
		OneTimeECDHKey:  oneTimeECDHSecretKey,
	}

	return private, public, nil
}

func RotateOneTimePreKey(private *UserPrivate, public *UserPublic) error {
	if private == nil || public == nil {
		return nil
	}

	oneTimeKyberPublicKey, oneTimeKyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return err
	}

	oneTimeECDHPublicKey, oneTimeECDHSecretKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return err
	}

	oneTimeKeyID, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}

	private.OneTimeKeyID = oneTimeKeyID
	private.OneTimeKyberKey = oneTimeKyberSecretKey
	private.OneTimeECDHKey = oneTimeECDHSecretKey

	public.OneTimeKeyID = oneTimeKeyID
	public.OneTimeKyberKey = oneTimeKyberPublicKey
	public.OneTimeECDHKey = oneTimeECDHPublicKey
	return nil
}

func BundleHash(keys *UserPublic) []byte {
	h := sha256.New()
	h.Write([]byte("skid-key-bundle-v1"))
	h.Write(keys.KyberKey)
	h.Write(keys.ECDHKey)
	h.Write(keys.Ed25519Key)
	h.Write(keys.OneTimeKeyID)
	h.Write(keys.OneTimeKyberKey)
	h.Write(keys.OneTimeECDHKey)
	return h.Sum(nil)
}

// LongTermIdentityHash returns a stable identity fingerprint for long-term keys
// only (without one-time prekeys).
func LongTermIdentityHash(keys *UserPublic) []byte {
	h := sha256.New()
	h.Write([]byte("skid-longterm-identity-v1"))
	h.Write(keys.KyberKey)
	h.Write(keys.ECDHKey)
	h.Write(keys.Ed25519Key)
	return h.Sum(nil)
}
