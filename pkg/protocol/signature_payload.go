package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func signaturePayload(m *EncryptedMessage) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("nil message")
	}

	var b bytes.Buffer
	b.WriteString("skid-signed-envelope-v1")

	if err := writeInt64(&b, m.CreatedAtUnix); err != nil {
		return nil, err
	}

	if err := writeField(&b, m.MessageID); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.ReceiverOneTimeKeyID); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.Ciphertext); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.IV); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.EncapsulatedKey); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrappedCekReceiver); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrapIVReceiver); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrapSaltReceiver); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.EncapsulatedKeySender); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrappedCekSender); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrapIVSender); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.WrapSaltSender); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.SenderIdentityHash); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.ReceiverIdentityHash); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.SenderBundleHash); err != nil {
		return nil, err
	}
	if err := writeField(&b, m.ReceiverBundleHash); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func writeField(b *bytes.Buffer, field []byte) error {
	if err := binary.Write(b, binary.BigEndian, uint32(len(field))); err != nil {
		return err
	}
	if len(field) > 0 {
		if _, err := b.Write(field); err != nil {
			return err
		}
	}
	return nil
}

func writeInt64(b *bytes.Buffer, v int64) error {
	return binary.Write(b, binary.BigEndian, v)
}
