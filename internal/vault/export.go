package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/alwin/sshm/pkg/models"
)

const (
	exportMagic   = "SSHMEXPORT"
	exportVersion = byte(0x01)
)

var (
	ErrInvalidExportFile = errors.New("invalid or corrupted SSHM export backup file")
)

// ExportBundle represents the decrypted content of an export backup file.
type ExportBundle struct {
	Profiles    []*models.SSHProfile                  `json:"profiles"`
	Credentials map[string]*models.ProfileCredentials `json:"credentials,omitempty"`
}

// ExportVault creates an encrypted backup file containing all profiles and their credentials.
func (v *Vault) ExportVault(destFile string, exportPassphrase string) error {
	if exportPassphrase == "" {
		return ErrPassphraseRequired
	}

	profiles, err := v.ListProfiles()
	if err != nil {
		return err
	}

	bundle := &ExportBundle{
		Profiles:    profiles,
		Credentials: make(map[string]*models.ProfileCredentials),
	}

	// If vault is unlocked and has credentials, include them in the bundle
	v.mu.Lock()
	if len(v.masterKey) == 32 && v.hasVaultFileUnsafe() {
		secrets, _, err := v.loadSecretsUnsafe()
		if err == nil {
			for name, creds := range secrets {
				if name != sentinelKey && creds != nil && !creds.IsEmpty() {
					bundle.Credentials[name] = creds
				}
			}
		}
	}
	v.mu.Unlock()

	payload, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to serialize export bundle: %w", err)
	}

	salt, err := GenerateRandomBytes(saltLen)
	if err != nil {
		return err
	}

	key := DeriveKey(exportPassphrase, salt)
	defer ZeroBytes(key)

	// Encrypt using export header
	envelope, err := EncryptExport(payload, key, salt)
	if err != nil {
		return err
	}

	return os.WriteFile(destFile, envelope, 0600)
}

// ImportVault reads and decrypts an encrypted backup file, then merges profiles and credentials.
func (v *Vault) ImportVault(srcFile string, importPassphrase string, overwrite bool) (int, error) {
	if importPassphrase == "" {
		return 0, ErrPassphraseRequired
	}

	envelope, err := os.ReadFile(srcFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read import file: %w", err)
	}

	plaintext, err := DecryptExport(envelope, importPassphrase)
	if err != nil {
		return 0, err
	}

	var bundle ExportBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return 0, fmt.Errorf("corrupted export payload: %w", err)
	}

	imported := 0
	for _, p := range bundle.Profiles {
		existing, _ := v.GetProfile(p.Name)
		if existing != nil && !overwrite {
			continue // skip existing profiles if not overwriting
		}

		if err := v.SaveProfile(p); err != nil {
			return imported, fmt.Errorf("failed to import profile %q: %w", p.Name, err)
		}

		// Import credentials if present
		if creds, ok := bundle.Credentials[p.Name]; ok && creds != nil {
			_ = v.SetCredentials(p.Name, creds)
		}

		imported++
	}

	return imported, nil
}

// EncryptExport encrypts an export bundle with AES-256-GCM using exportMagic.
func EncryptExport(plaintext, key, salt []byte) ([]byte, error) {
	aad := append([]byte(exportMagic), exportVersion)
	aad = append(aad, salt...)

	nonce, err := GenerateRandomBytes(nonceLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, len(aad)+len(nonce)+len(ciphertext))
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptExport decrypts an export envelope using the import passphrase.
func DecryptExport(envelope []byte, passphrase string) ([]byte, error) {
	headerLen := len(exportMagic) + 1 + saltLen
	minLen := headerLen + nonceLen + 16
	if len(envelope) < minLen {
		return nil, ErrInvalidExportFile
	}

	if subtle.ConstantTimeCompare(envelope[:len(exportMagic)], []byte(exportMagic)) != 1 {
		return nil, ErrInvalidExportFile
	}

	salt := envelope[len(exportMagic)+1 : headerLen]
	key := DeriveKey(passphrase, salt)
	defer ZeroBytes(key)

	aad := envelope[:headerLen]
	nonce := envelope[headerLen : headerLen+nonceLen]
	ciphertext := envelope[headerLen+nonceLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	return plaintext, nil
}
