package protocol

import (
	"skid/internal/crypto"
	"skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, receiverPublicKeys *identity.UserPublic, receiverPrivateKeys *identity.UserPrivate, senderPublicKeys *identity.UserPublic, isAuthor bool) ([]byte, error) {
	var cek []byte
	var err error

	if isAuthor {
		ssSender, err := crypto.HybridDecrypt(
			receiverPublicKeys.ECDHKey,
			receiverPrivateKeys.ECDHKey,
			receiverPrivateKeys.KyberKey,
			encrypted.EncapsulatedKeySender,
		)
		if err != nil {
			return nil, err
		}

		kekSender, err := crypto.DeriveAesKey(ssSender, encrypted.WrapSaltSender)
		if err != nil {
			return nil, err
		}

		cek, err = crypto.Decrypt(kekSender, encrypted.WrapIVSender, encrypted.WrappedCekSender)
		if err != nil {
			return nil, err
		}
	} else {
		ssReceiver, err := crypto.HybridDecrypt(
			senderPublicKeys.ECDHKey,
			receiverPrivateKeys.ECDHKey,
			receiverPrivateKeys.KyberKey,
			encrypted.EncapsulatedKey,
		)
		if err != nil {
			return nil, err
		}

		kekReceiver, err := crypto.DeriveAesKey(ssReceiver, encrypted.WrapSaltReceiver)
		if err != nil {
			return nil, err
		}

		cek, err = crypto.Decrypt(kekReceiver, encrypted.WrapIVReceiver, encrypted.WrappedCekReceiver)
		if err != nil {
			return nil, err
		}
	}

	plaintext, err := crypto.Decrypt(cek, encrypted.IV, encrypted.Ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
