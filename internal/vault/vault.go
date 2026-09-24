package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/alwin/sshm/internal/config"
	"github.com/alwin/sshm/internal/logging"
	"github.com/alwin/sshm/pkg/models"
)

const (
	sentinelKey   = "__sshm_sentinel__"
	sentinelValue = "valid_vault_v1"
)

var (
	ErrVaultLocked        = errors.New("vault is locked; please unlock with 'sshm vault unlock' or provide master passphrase")
	ErrProfileNotFound    = errors.New("profile not found")
	ErrProfileExists      = errors.New("profile already exists")
	ErrPassphraseRequired = errors.New("master passphrase is required")
)

// VaultStatus provides information about the current vault state.
type VaultStatus struct {
	IsLocked         bool   `json:"is_locked"`
	HasVaultFile     bool   `json:"has_vault_file"`
	HasProfilesFile  bool   `json:"has_profiles_file"`
	KeyringAvailable bool   `json:"keyring_available"`
	KeyringActive    bool   `json:"keyring_active"`
	ProfileCount     int    `json:"profile_count"`
	ProfilesPath     string `json:"profiles_path"`
	VaultPath        string `json:"vault_path"`
}

// Vault manages SSH profiles and their encrypted credentials.
type Vault struct {
	profilesPath string
	vaultPath    string
	keyring      KeyringStorage
	masterKey    []byte
	mu           sync.RWMutex
}

// NewVault initializes a Vault instance.
func NewVault(keyring KeyringStorage) (*Vault, error) {
	if _, err := config.EnsureConfigDir(); err != nil {
		return nil, err
	}

	pPath, err := config.GetProfilesPath()
	if err != nil {
		return nil, err
	}

	vPath, err := config.GetVaultPath()
	if err != nil {
		return nil, err
	}

	if keyring == nil {
		keyring = NewOSKeyring()
	}

	v := &Vault{
		profilesPath: pPath,
		vaultPath:    vPath,
		keyring:      keyring,
	}

	// Try loading cached master key from keyring at startup
	if k, err := keyring.GetMasterKey(); err == nil && len(k) == 32 {
		v.masterKey = k
		logging.Debugf("Loaded master key from OS keyring")
	}

	return v, nil
}

// Status returns current status of the vault.
func (v *Vault) Status() (*VaultStatus, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	hasV := false
	if _, err := os.Stat(v.vaultPath); err == nil {
		hasV = true
	}

	hasP := false
	var profiles []*models.SSHProfile
	if data, err := os.ReadFile(v.profilesPath); err == nil {
		hasP = true
		_ = json.Unmarshal(data, &profiles)
	}

	keyringAvail := v.keyring.IsAvailable()
	keyringActive := false
	if k, err := v.keyring.GetMasterKey(); err == nil && len(k) == 32 {
		keyringActive = true
	}

	isLocked := true
	if len(v.masterKey) == 32 || keyringActive {
		isLocked = false
	}

	return &VaultStatus{
		IsLocked:         isLocked,
		HasVaultFile:     hasV,
		HasProfilesFile:  hasP,
		KeyringAvailable: keyringAvail,
		KeyringActive:    keyringActive,
		ProfileCount:     len(profiles),
		ProfilesPath:     v.profilesPath,
		VaultPath:        v.vaultPath,
	}, nil
}

// Initialize creates a new vault with the provided master passphrase.
func (v *Vault) Initialize(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if passphrase == "" {
		return ErrPassphraseRequired
	}

	salt, err := GenerateRandomBytes(saltLen)
	if err != nil {
		return err
	}

	key := DeriveKey(passphrase, salt)

	// Create initial secrets map with sentinel
	initialSecrets := map[string]*models.ProfileCredentials{
		sentinelKey: {Password: sentinelValue},
	}
	payload, err := json.Marshal(initialSecrets)
	if err != nil {
		return err
	}

	envelope, err := Encrypt(payload, key, salt)
	if err != nil {
		return err
	}

	if err := os.WriteFile(v.vaultPath, envelope, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	// Also ensure profiles.json exists
	if _, err := os.Stat(v.profilesPath); os.IsNotExist(err) {
		emptyList := []*models.SSHProfile{}
		data, _ := json.MarshalIndent(emptyList, "", "  ")
		_ = os.WriteFile(v.profilesPath, data, 0600)
	}

	v.masterKey = key
	if v.keyring.IsAvailable() {
		_ = v.keyring.SetMasterKey(key)
	}

	return nil
}

// Lock removes the master key from memory and clears it from OS keyring.
func (v *Vault) Lock() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	ZeroBytes(v.masterKey)
	v.masterKey = nil

	_ = v.keyring.DeleteMasterKey()
	return nil
}

// Unlock unlocks the vault using the supplied master passphrase.
func (v *Vault) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if passphrase == "" {
		return ErrPassphraseRequired
	}

	envelope, err := os.ReadFile(v.vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Initialize vault if not exists yet
			v.mu.Unlock()
			err := v.Initialize(passphrase)
			v.mu.Lock()
			return err
		}
		return fmt.Errorf("failed to read vault file: %w", err)
	}

	salt, err := ExtractSalt(envelope)
	if err != nil {
		return err
	}

	key := DeriveKey(passphrase, salt)
	plaintext, err := Decrypt(envelope, key)
	if err != nil {
		ZeroBytes(key)
		return ErrWrongPassphrase
	}

	// Verify sentinel
	var secrets map[string]*models.ProfileCredentials
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		ZeroBytes(key)
		return ErrInvalidCiphertext
	}
	if s, ok := secrets[sentinelKey]; !ok || s.Password != sentinelValue {
		ZeroBytes(key)
		return ErrWrongPassphrase
	}

	v.masterKey = key
	if v.keyring.IsAvailable() {
		_ = v.keyring.SetMasterKey(key)
	}

	return nil
}

// EnsureUnlocked ensures the master key is loaded. If locked, calls promptFn to obtain passphrase.
func (v *Vault) EnsureUnlocked(promptFn func() (string, error)) error {
	v.mu.Lock()
	if len(v.masterKey) == 32 {
		v.mu.Unlock()
		return nil
	}

	// Try reading from keyring
	if k, err := v.keyring.GetMasterKey(); err == nil && len(k) == 32 {
		// Test key against vault file
		if envelope, err := os.ReadFile(v.vaultPath); err == nil {
			if _, decErr := Decrypt(envelope, k); decErr == nil {
				v.masterKey = k
				v.mu.Unlock()
				return nil
			}
		}
	}
	v.mu.Unlock()

	// If vault file doesn't exist yet, there are no encrypted credentials to unlock
	if _, err := os.Stat(v.vaultPath); os.IsNotExist(err) {
		return nil
	}

	if promptFn == nil {
		return ErrVaultLocked
	}

	pass, err := promptFn()
	if err != nil {
		return err
	}

	return v.Unlock(pass)
}

// EnsureInitialized ensures the vault is initialized and unlocked so new credentials can be stored.
func (v *Vault) EnsureInitialized(promptFn func() (string, error)) error {
	v.mu.Lock()
	if len(v.masterKey) == 32 {
		v.mu.Unlock()
		return nil
	}
	v.mu.Unlock()

	if _, err := os.Stat(v.vaultPath); os.IsNotExist(err) {
		if promptFn == nil {
			return ErrVaultLocked
		}
		pass, err := promptFn()
		if err != nil {
			return err
		}
		return v.Initialize(pass)
	}

	return v.EnsureUnlocked(promptFn)
}

// ======================== PROFILE OPERATIONS (METADATA) ========================

// ListProfiles returns all profiles sorted by name.
func (v *Vault) ListProfiles() ([]*models.SSHProfile, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	data, err := os.ReadFile(v.profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*models.SSHProfile{}, nil
		}
		return nil, fmt.Errorf("failed to read profiles: %w", err)
	}

	var profiles []*models.SSHProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("failed to parse profiles: %w", err)
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	return profiles, nil
}

// GetProfile finds a profile by its unique name.
func (v *Vault) GetProfile(name string) (*models.SSHProfile, error) {
	profiles, err := v.ListProfiles()
	if err != nil {
		return nil, err
	}

	for _, p := range profiles {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrProfileNotFound, name)
}

// SaveProfile saves or updates a profile in the metadata store.
func (v *Vault) SaveProfile(profile *models.SSHProfile) error {
	if err := profile.Validate(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	profiles, err := v.loadProfilesUnsafe()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	found := false
	for i, p := range profiles {
		if p.Name == profile.Name {
			profile.CreatedAt = p.CreatedAt
			profile.UpdatedAt = now
			profiles[i] = profile
			found = true
			break
		}
	}

	if !found {
		profile.CreatedAt = now
		profile.UpdatedAt = now
		profiles = append(profiles, profile)
	}

	return v.saveProfilesUnsafe(profiles)
}

// RenameProfile updates a profile name and preserves associated credentials in the encrypted vault.
func (v *Vault) RenameProfile(oldName, newName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	profiles, err := v.loadProfilesUnsafe()
	if err != nil {
		return err
	}

	// Ensure newName doesn't already exist
	for _, p := range profiles {
		if p.Name == newName {
			return fmt.Errorf("%w: profile %q already exists", ErrProfileExists, newName)
		}
	}

	var target *models.SSHProfile
	for _, p := range profiles {
		if p.Name == oldName {
			target = p
			break
		}
	}

	if target == nil {
		return fmt.Errorf("%w: %q", ErrProfileNotFound, oldName)
	}

	target.Name = newName
	target.UpdatedAt = time.Now().UTC()
	if err := target.Validate(); err != nil {
		return err
	}

	if err := v.saveProfilesUnsafe(profiles); err != nil {
		return err
	}

	// Rename in encrypted secrets if vault is initialized
	if len(v.masterKey) == 32 && v.hasVaultFileUnsafe() {
		secrets, salt, err := v.loadSecretsUnsafe()
		if err == nil {
			if creds, ok := secrets[oldName]; ok {
				delete(secrets, oldName)
				secrets[newName] = creds
				_ = v.saveSecretsUnsafe(secrets, salt)
			}
		}
	}

	return nil
}

// DeleteProfile deletes a profile and wipes its credentials from the vault.
func (v *Vault) DeleteProfile(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	profiles, err := v.loadProfilesUnsafe()
	if err != nil {
		return err
	}

	foundIdx := -1
	for i, p := range profiles {
		if p.Name == name {
			foundIdx = i
			break
		}
	}

	if foundIdx == -1 {
		return fmt.Errorf("%w: %q", ErrProfileNotFound, name)
	}

	profiles = append(profiles[:foundIdx], profiles[foundIdx+1:]...)
	if err := v.saveProfilesUnsafe(profiles); err != nil {
		return err
	}

	// Delete from secrets if vault is initialized
	if len(v.masterKey) == 32 && v.hasVaultFileUnsafe() {
		secrets, salt, err := v.loadSecretsUnsafe()
		if err == nil {
			if creds, ok := secrets[name]; ok {
				creds.Zero()
				delete(secrets, name)
				_ = v.saveSecretsUnsafe(secrets, salt)
			}
		}
	}

	return nil
}

// ======================== CREDENTIAL OPERATIONS (SECRETS) ========================

// GetCredentials retrieves decrypted credentials for a profile.
func (v *Vault) GetCredentials(profileName string) (*models.ProfileCredentials, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.masterKey) != 32 {
		return nil, ErrVaultLocked
	}

	if !v.hasVaultFileUnsafe() {
		return nil, nil
	}

	secrets, _, err := v.loadSecretsUnsafe()
	if err != nil {
		return nil, err
	}

	creds, ok := secrets[profileName]
	if !ok || creds == nil {
		return nil, nil
	}

	return creds, nil
}

// SetCredentials encrypts and stores credentials for a profile.
func (v *Vault) SetCredentials(profileName string, creds *models.ProfileCredentials) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.masterKey) != 32 {
		return ErrVaultLocked
	}

	secrets, salt, err := v.loadSecretsUnsafe()
	if err != nil {
		return err
	}

	secrets[profileName] = creds
	return v.saveSecretsUnsafe(secrets, salt)
}

// DeleteCredentials removes credentials for a profile from the vault.
func (v *Vault) DeleteCredentials(profileName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.masterKey) != 32 {
		return ErrVaultLocked
	}

	if !v.hasVaultFileUnsafe() {
		return nil
	}

	secrets, salt, err := v.loadSecretsUnsafe()
	if err != nil {
		return err
	}

	if c, ok := secrets[profileName]; ok {
		c.Zero()
		delete(secrets, profileName)
	}

	return v.saveSecretsUnsafe(secrets, salt)
}

// ======================== INTERNAL HELPERS ========================

func (v *Vault) hasVaultFileUnsafe() bool {
	_, err := os.Stat(v.vaultPath)
	return err == nil
}

func (v *Vault) loadProfilesUnsafe() ([]*models.SSHProfile, error) {
	data, err := os.ReadFile(v.profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*models.SSHProfile{}, nil
		}
		return nil, err
	}
	var profiles []*models.SSHProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, err
	}
	return profiles, nil
}

func (v *Vault) saveProfilesUnsafe(profiles []*models.SSHProfile) error {
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.profilesPath, data, 0600)
}

func (v *Vault) loadSecretsUnsafe() (map[string]*models.ProfileCredentials, []byte, error) {
	envelope, err := os.ReadFile(v.vaultPath)
	if err != nil {
		return nil, nil, err
	}

	salt, err := ExtractSalt(envelope)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := Decrypt(envelope, v.masterKey)
	if err != nil {
		return nil, nil, err
	}

	var secrets map[string]*models.ProfileCredentials
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, nil, err
	}

	return secrets, salt, nil
}

func (v *Vault) saveSecretsUnsafe(secrets map[string]*models.ProfileCredentials, salt []byte) error {
	// Ensure sentinel is present
	secrets[sentinelKey] = &models.ProfileCredentials{Password: sentinelValue}

	payload, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	envelope, err := Encrypt(payload, v.masterKey, salt)
	if err != nil {
		return err
	}

	return os.WriteFile(v.vaultPath, envelope, 0600)
}
