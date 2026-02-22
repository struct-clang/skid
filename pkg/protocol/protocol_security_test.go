package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slipe-fun/skid/pkg/identity"
)

func newUsers(t *testing.T) (*identity.UserPrivate, *identity.UserPublic, *identity.UserPrivate, *identity.UserPublic) {
	t.Helper()
	alicePrivate, alicePublic, err := identity.NewUser()
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bobPrivate, bobPublic, err := identity.NewUser()
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	return alicePrivate, alicePublic, bobPrivate, bobPublic
}

func setupReplayStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "replay_store.json")
	SetReplayStorePath(path)
	return path
}

func cloneMessage(m *EncryptedMessage) *EncryptedMessage {
	out := *m
	out.MessageID = append([]byte{}, m.MessageID...)
	out.ReceiverOneTimeKeyID = append([]byte{}, m.ReceiverOneTimeKeyID...)
	out.Ciphertext = append([]byte{}, m.Ciphertext...)
	out.IV = append([]byte{}, m.IV...)
	out.EncapsulatedKey = append([]byte{}, m.EncapsulatedKey...)
	out.WrappedCekReceiver = append([]byte{}, m.WrappedCekReceiver...)
	out.WrapIVReceiver = append([]byte{}, m.WrapIVReceiver...)
	out.WrapSaltReceiver = append([]byte{}, m.WrapSaltReceiver...)
	out.EncapsulatedKeySender = append([]byte{}, m.EncapsulatedKeySender...)
	out.WrappedCekSender = append([]byte{}, m.WrappedCekSender...)
	out.WrapIVSender = append([]byte{}, m.WrapIVSender...)
	out.WrapSaltSender = append([]byte{}, m.WrapSaltSender...)
	out.SenderIdentityHash = append([]byte{}, m.SenderIdentityHash...)
	out.ReceiverIdentityHash = append([]byte{}, m.ReceiverIdentityHash...)
	out.SenderBundleHash = append([]byte{}, m.SenderBundleHash...)
	out.ReceiverBundleHash = append([]byte{}, m.ReceiverBundleHash...)
	out.Signature = append([]byte{}, m.Signature...)
	return &out
}

func nowUnix() int64 {
	return time.Now().Unix()
}

func TestReplayIsMarkedOnlyAfterSuccessfulDecrypt(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, bobPrivate, bobPublic := newUsers(t)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tampered := cloneMessage(msg)
	tampered.Ciphertext[0] ^= 0xFF
	if _, err := Decrypt(tampered, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic)); err == nil {
		t.Fatalf("expected decrypt failure for tampered message")
	}

	plaintext, err := Decrypt(msg, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic))
	if err != nil {
		t.Fatalf("expected second decrypt to succeed after failed attempt: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
}

func TestReplayReservationBlocksDuplicatesUntilResolved(t *testing.T) {
	setupReplayStore(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	msgID := []byte("0123456789abcdef")

	reservation, err := beginReplayReservation(key, msgID, nowUnix())
	if err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}

	if _, err := beginReplayReservation(key, msgID, nowUnix()); err == nil {
		t.Fatalf("expected duplicate pending reservation to fail")
	}

	if err := reservation.Cancel(); err != nil {
		t.Fatalf("cancel reservation: %v", err)
	}

	reservation2, err := beginReplayReservation(key, msgID, nowUnix())
	if err != nil {
		t.Fatalf("reservation after cancel should succeed: %v", err)
	}
	if err := reservation2.Commit(); err != nil {
		t.Fatalf("commit reservation: %v", err)
	}
	if _, err := beginReplayReservation(key, msgID, nowUnix()); err == nil {
		t.Fatalf("expected replay after commit")
	}
}

func TestDecryptRejectsOversizedCiphertext(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, bobPrivate, bobPublic := newUsers(t)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	msg.Ciphertext = make([]byte, maxCiphertextSize+1)

	if _, err := Decrypt(msg, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic)); err == nil || !strings.Contains(err.Error(), "ciphertext exceeds maximum size") {
		t.Fatalf("expected oversized ciphertext error, got: %v", err)
	}
}

func TestEncryptInvalidEd25519KeyReturnsError(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, _, bobPublic := newUsers(t)
	alicePrivate.Ed25519Key = []byte("bad")

	if _, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic)); err == nil {
		t.Fatalf("expected encrypt to fail on invalid ed25519 private key")
	}
}

func TestReplayStoreTamperIsRejected(t *testing.T) {
	path := setupReplayStore(t)
	alicePrivate, alicePublic, bobPrivate, bobPublic := newUsers(t)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(msg, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic)); err != nil {
		t.Fatalf("initial decrypt: %v", err)
	}

	if err := os.WriteFile(path, []byte("{corrupted"), 0o600); err != nil {
		t.Fatalf("write corrupted replay store: %v", err)
	}

	msg2, err := Encrypt("hello2", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt second: %v", err)
	}
	if _, err := Decrypt(msg2, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic)); err == nil || !strings.Contains(err.Error(), "decode replay store") {
		t.Fatalf("expected replay store decode failure, got: %v", err)
	}
}

func TestDecryptDoesNotMutateOneTimeKeys(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, bobPrivate, bobPublic := newUsers(t)

	originalPubID := append([]byte{}, bobPublic.OneTimeKeyID...)
	originalPrivID := append([]byte{}, bobPrivate.OneTimeKeyID...)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(msg, bobPublic, bobPrivate, alicePublic, false, identity.LongTermIdentityHash(alicePublic)); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(originalPubID) != string(bobPublic.OneTimeKeyID) {
		t.Fatalf("public one-time key id was mutated")
	}
	if string(originalPrivID) != string(bobPrivate.OneTimeKeyID) {
		t.Fatalf("private one-time key id was mutated")
	}
}

func TestAuthorSideDecryptIsDisabled(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, _, bobPublic := newUsers(t)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(msg, alicePublic, alicePrivate, alicePublic, true, identity.LongTermIdentityHash(alicePublic)); err == nil || !strings.Contains(err.Error(), "disabled for forward secrecy") {
		t.Fatalf("expected author-side decrypt to be disabled, got: %v", err)
	}
}

func TestDecryptRejectsUnexpectedSenderIdentity(t *testing.T) {
	setupReplayStore(t)
	alicePrivate, alicePublic, bobPrivate, bobPublic := newUsers(t)

	msg, err := Encrypt("hello", alicePublic, alicePrivate, bobPublic, identity.LongTermIdentityHash(bobPublic))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongHash := make([]byte, 32)
	copy(wrongHash, identity.LongTermIdentityHash(alicePublic))
	wrongHash[0] ^= 0xFF

	if _, err := Decrypt(msg, bobPublic, bobPrivate, alicePublic, false, wrongHash); err == nil || !strings.Contains(err.Error(), "unexpected sender identity hash") {
		t.Fatalf("expected sender identity mismatch, got: %v", err)
	}
}
