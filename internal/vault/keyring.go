package vault

import (
	"encoding/hex"
	"fmt"

	"github.com/kulangaraalwinjoy/sshm/internal/logging"
	"github.com/zalando/go-keyring"
)

const (
	keyringService = "sshm"
	keyringUser    = "master-key"
)

// KeyringStorage interface defines operations for storing and retrieving the master encryption key.
type KeyringStorage interface {
	GetMasterKey() ([]byte, error)
	SetMasterKey(key []byte) error
	DeleteMasterKey() error
	IsAvailable() bool
}

// OSKeyring implements KeyringStorage using the platform's native secure keyring.
type OSKeyring struct{}

// NewOSKeyring creates an OSKeyring instance.
func NewOSKeyring() *OSKeyring {
	return &OSKeyring{}
}

// GetMasterKey retrieves the master key from the OS keyring.
func (k *OSKeyring) GetMasterKey() ([]byte, error) {
	val, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		logging.Debugf("OS Keyring Get failed or empty: %v", err)
		return nil, err
	}
	key, err := hex.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("corrupted keyring entry: %w", err)
	}
	return key, nil
}

// SetMasterKey stores the master key in the OS keyring.
func (k *OSKeyring) SetMasterKey(key []byte) error {
	encoded := hex.EncodeToString(key)
	if err := keyring.Set(keyringService, keyringUser, encoded); err != nil {
		logging.Debugf("OS Keyring Set failed: %v", err)
		return err
	}
	return nil
}

// DeleteMasterKey removes the master key from the OS keyring.
func (k *OSKeyring) DeleteMasterKey() error {
	err := keyring.Delete(keyringService, keyringUser)
	if err != nil {
		logging.Debugf("OS Keyring Delete: %v", err)
	}
	return err
}

// IsAvailable checks if the OS keyring is accessible.
func (k *OSKeyring) IsAvailable() bool {
	// Test availability with a temporary probe key
	testKey := "__probe__"
	if err := keyring.Set(keyringService, testKey, "1"); err != nil {
		return false
	}
	_ = keyring.Delete(keyringService, testKey)
	return true
}

// MemoryKeyring is an in-memory implementation for testing or headless environments where no OS keyring exists.
type MemoryKeyring struct {
	stored []byte
}

func NewMemoryKeyring() *MemoryKeyring {
	return &MemoryKeyring{}
}

func (m *MemoryKeyring) GetMasterKey() ([]byte, error) {
	if len(m.stored) == 0 {
		return nil, fmt.Errorf("keyring empty")
	}
	cp := make([]byte, len(m.stored))
	copy(cp, m.stored)
	return cp, nil
}

func (m *MemoryKeyring) SetMasterKey(key []byte) error {
	m.stored = make([]byte, len(key))
	copy(m.stored, key)
	return nil
}

func (m *MemoryKeyring) DeleteMasterKey() error {
	ZeroBytes(m.stored)
	m.stored = nil
	return nil
}

func (m *MemoryKeyring) IsAvailable() bool {
	return true
}
