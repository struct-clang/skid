package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/slipe-fun/skid/internal/crypto"
	"golang.org/x/sys/unix"
)

var (
	replayMu       sync.Mutex
	replayOnce     sync.Once
	replayStoreErr error
	replayStore    string
	replayMacKey   []byte
)

const (
	maxFutureSkew     = 2 * time.Minute
	maxMessageAge     = 24 * time.Hour
	pendingTTL        = 10 * time.Minute
	maxReplayFileSize = 16 << 20
	maxSeenEntries    = 200000
	maxPendingEntries = 20000
)

type replayDiskState struct {
	Version int `json:"version"`

	// Version 2 fields.
	Seen    map[string]int64 `json:"seen,omitempty"`
	Pending map[string]int64 `json:"pending,omitempty"`

	// Legacy Version 1 field.
	Entries map[string]int64 `json:"entries,omitempty"`
}

type replayDiskEnvelope struct {
	Version int              `json:"version"`
	State   *replayDiskState `json:"state"`
	MAC     string           `json:"mac"`
}

type replayReservation struct {
	key       string
	committed bool
}

// SetReplayStorePath allows configuring a custom persistent replay-store path.
// It must be called before any Encrypt/Decrypt call that touches replay checks.
func SetReplayStorePath(path string) {
	replayMu.Lock()
	defer replayMu.Unlock()
	replayStore = path
	replayMacKey = nil
	replayOnce = sync.Once{}
	replayStoreErr = nil
}

func beginReplayReservation(receiverBundleHash, messageID []byte, createdAtUnix int64) (*replayReservation, error) {
	if err := validateReplayFields(receiverBundleHash, messageID, createdAtUnix); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s:%s", hex.EncodeToString(receiverBundleHash), hex.EncodeToString(messageID))
	if err := withReplayStateLocked(func(state *replayDiskState) error {
		if _, exists := state.Seen[key]; exists {
			return errors.New("replay detected")
		}
		if _, exists := state.Pending[key]; exists {
			return errors.New("message is already being processed")
		}
		if len(state.Pending) >= maxPendingEntries {
			return errors.New("replay pending queue is full")
		}
		state.Pending[key] = time.Now().Unix()
		return nil
	}); err != nil {
		return nil, err
	}

	return &replayReservation{key: key}, nil
}

func (r *replayReservation) Commit() error {
	if r == nil {
		return errors.New("nil replay reservation")
	}
	if r.committed {
		return nil
	}
	if err := withReplayStateLocked(func(state *replayDiskState) error {
		delete(state.Pending, r.key)
		state.Seen[r.key] = time.Now().Unix()
		return nil
	}); err != nil {
		return err
	}

	r.committed = true
	return nil
}

func (r *replayReservation) Cancel() error {
	if r == nil || r.committed {
		return nil
	}
	return withReplayStateLocked(func(state *replayDiskState) error {
		delete(state.Pending, r.key)
		return nil
	})
}

func validateReplayFields(receiverBundleHash, messageID []byte, createdAtUnix int64) error {
	if len(receiverBundleHash) == 0 {
		return errors.New("missing receiver bundle hash")
	}
	if len(messageID) != oneTimeKeyIDSize {
		return errors.New("invalid message id")
	}

	createdAt := time.Unix(createdAtUnix, 0)
	now := time.Now()
	if createdAt.After(now.Add(maxFutureSkew)) {
		return errors.New("message timestamp is in the future")
	}
	if createdAt.Before(now.Add(-maxMessageAge)) {
		return errors.New("message is too old")
	}
	return nil
}

func initReplayStore() {
	path, err := resolveReplayStorePath()
	if err != nil {
		replayStoreErr = err
		return
	}
	replayStore = path

	if err := os.MkdirAll(filepath.Dir(replayStore), 0o700); err != nil {
		replayStoreErr = fmt.Errorf("create replay store dir: %w", err)
		return
	}
}

func resolveReplayStorePath() (string, error) {
	if replayStore != "" {
		return replayStore, nil
	}

	stateDir := os.Getenv("XDG_STATE_HOME")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home dir: %w", err)
		}
		stateDir = filepath.Join(home, ".local", "state")
	}

	return filepath.Join(stateDir, "skid", "replay_store.json"), nil
}

func withReplayStateLocked(fn func(*replayDiskState) error) error {
	replayOnce.Do(initReplayStore)
	if replayStoreErr != nil {
		return fmt.Errorf("replay store init failed: %w", replayStoreErr)
	}

	lockPath := replayStore + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open replay lock file: %w", err)
	}
	defer lockFile.Close()

	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("acquire replay lock: %w", err)
	}
	defer func() { _ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) }()

	state, err := loadReplayStateLocked()
	if err != nil {
		return err
	}
	cleanupReplayState(state, time.Now())

	if err := fn(state); err != nil {
		return err
	}

	return saveReplayStateLocked(state)
}

func loadReplayStateLocked() (*replayDiskState, error) {
	data, err := os.ReadFile(replayStore)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &replayDiskState{
				Version: 2,
				Seen:    map[string]int64{},
				Pending: map[string]int64{},
			}, nil
		}
		return nil, fmt.Errorf("read replay store: %w", err)
	}
	if len(data) > maxReplayFileSize {
		return nil, fmt.Errorf("replay store exceeds maximum size: %d", len(data))
	}

	// Preferred v3 format with integrity MAC.
	var envelope replayDiskEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Version == 3 && envelope.State != nil {
		macKey, err := loadOrCreateReplayMACKeyLocked()
		if err != nil {
			return nil, err
		}
		expectedMAC, err := computeReplayMAC(envelope.State, macKey)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(expectedMAC), []byte(envelope.MAC)) != 1 {
			return nil, errors.New("replay store integrity check failed")
		}
		return normalizeReplayState(envelope.State), nil
	}

	// Backward-compatible migration for v1/v2 (without MAC).
	var state replayDiskState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode replay store: %w", err)
	}
	return normalizeReplayState(&state), nil
}

func normalizeReplayState(state *replayDiskState) *replayDiskState {
	if state == nil {
		return &replayDiskState{Version: 2, Seen: map[string]int64{}, Pending: map[string]int64{}}
	}

	switch state.Version {
	case 1:
		return &replayDiskState{
			Version: 2,
			Seen:    cloneMap(state.Entries),
			Pending: map[string]int64{},
		}
	case 2:
		if state.Seen == nil {
			state.Seen = map[string]int64{}
		}
		if state.Pending == nil {
			state.Pending = map[string]int64{}
		}
		return state
	default:
		return &replayDiskState{Version: 2, Seen: map[string]int64{}, Pending: map[string]int64{}}
	}
}

func cleanupReplayState(state *replayDiskState, now time.Time) {
	seenCutoff := now.Add(-maxMessageAge).Unix()
	for key, ts := range state.Seen {
		if ts < seenCutoff {
			delete(state.Seen, key)
		}
	}

	pendingCutoff := now.Add(-pendingTTL).Unix()
	for key, ts := range state.Pending {
		if ts < pendingCutoff {
			delete(state.Pending, key)
		}
	}

	evictOldest(state.Seen, maxSeenEntries)
	evictOldest(state.Pending, maxPendingEntries)
}

func evictOldest(entries map[string]int64, maxEntries int) {
	if len(entries) <= maxEntries {
		return
	}
	type kv struct {
		key string
		ts  int64
	}
	pairs := make([]kv, 0, len(entries))
	for k, ts := range entries {
		pairs = append(pairs, kv{key: k, ts: ts})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].ts < pairs[j].ts })
	toRemove := len(entries) - maxEntries
	for i := 0; i < toRemove; i++ {
		delete(entries, pairs[i].key)
	}
}

func saveReplayStateLocked(state *replayDiskState) error {
	state.Version = 2
	macKey, err := loadOrCreateReplayMACKeyLocked()
	if err != nil {
		return err
	}
	mac, err := computeReplayMAC(state, macKey)
	if err != nil {
		return err
	}
	envelope := replayDiskEnvelope{Version: 3, State: state, MAC: mac}

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode replay store: %w", err)
	}
	if len(data) > maxReplayFileSize {
		return fmt.Errorf("replay store exceeds maximum size: %d", len(data))
	}

	tmpPath := replayStore + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write replay store tmp: %w", err)
	}
	if err := os.Rename(tmpPath, replayStore); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace replay store: %w", err)
	}

	return nil
}

func loadOrCreateReplayMACKeyLocked() ([]byte, error) {
	if len(replayMacKey) == 32 {
		return replayMacKey, nil
	}

	keyPath := replayStore + ".key"
	data, err := os.ReadFile(keyPath)
	if err == nil {
		if len(data) != 32 {
			return nil, errors.New("invalid replay mac key length")
		}
		replayMacKey = append([]byte{}, data...)
		return replayMacKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read replay mac key: %w", err)
	}

	key, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate replay mac key: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write replay mac key: %w", err)
	}
	replayMacKey = key
	return replayMacKey, nil
}

func computeReplayMAC(state *replayDiskState, key []byte) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("encode replay state for mac: %w", err)
	}
	m := hmac.New(sha256.New, key)
	if _, err := m.Write([]byte("skid-replay-store-v1")); err != nil {
		return "", err
	}
	if _, err := m.Write(payload); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

func cloneMap(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
