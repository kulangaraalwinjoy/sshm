package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kulangaraalwinjoy/sshm/internal/config"
	"github.com/kulangaraalwinjoy/sshm/pkg/models"
)

func setupTestVault(t *testing.T) (*Vault, string) {
	tempDir := t.TempDir()
	config.SetCustomConfigDir(tempDir)

	memKeyring := NewMemoryKeyring()
	v, err := NewVault(memKeyring)
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	return v, tempDir
}

func TestVaultInitializationAndUnlock(t *testing.T) {
	v, _ := setupTestVault(t)

	status, err := v.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.IsLocked {
		t.Errorf("expected new uninitialized vault to be locked")
	}

	pass := "MasterPassphrase123!"
	if err := v.Initialize(pass); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	status, err = v.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if status.IsLocked {
		t.Errorf("expected vault to be unlocked after Initialize")
	}

	// Test lock
	if err := v.Lock(); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	status, _ = v.Status()
	if !status.IsLocked {
		t.Errorf("expected vault to be locked after Lock()")
	}

	// Test unlock with wrong passphrase
	err = v.Unlock("wrong-passphrase")
	if err == nil {
		t.Fatalf("expected Unlock to fail with wrong passphrase")
	}

	// Test unlock with correct passphrase
	err = v.Unlock(pass)
	if err != nil {
		t.Fatalf("Unlock failed with correct passphrase: %v", err)
	}
	status, _ = v.Status()
	if status.IsLocked {
		t.Errorf("expected vault to be unlocked after valid Unlock()")
	}
}

func TestProfileAndCredentialCRUD(t *testing.T) {
	v, _ := setupTestVault(t)
	pass := "MasterPassphrase123!"
	if err := v.Initialize(pass); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	p := models.NewSSHProfile("production", "192.168.1.50", 22, "ubuntu")
	p.AuthMethod = models.AuthMethodPassword

	// Save profile
	if err := v.SaveProfile(p); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}

	// Save credentials
	creds := &models.ProfileCredentials{
		Password: "supersecretpassword",
	}
	if err := v.SetCredentials("production", creds); err != nil {
		t.Fatalf("SetCredentials failed: %v", err)
	}

	// Read profile
	readP, err := v.GetProfile("production")
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}
	if readP.Host != "192.168.1.50" || readP.Username != "ubuntu" {
		t.Errorf("read profile fields mismatch: %+v", readP)
	}

	// Read credentials
	readCreds, err := v.GetCredentials("production")
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}
	if readCreds == nil || readCreds.Password != "supersecretpassword" {
		t.Errorf("read credentials mismatch: %+v", readCreds)
	}

	// Rename profile
	if err := v.RenameProfile("production", "prod-eu"); err != nil {
		t.Fatalf("RenameProfile failed: %v", err)
	}

	// Verify old name is gone
	_, err = v.GetProfile("production")
	if err == nil {
		t.Errorf("expected old profile name to be gone")
	}

	// Verify new name exists with credentials preserved
	newP, err := v.GetProfile("prod-eu")
	if err != nil {
		t.Fatalf("GetProfile(prod-eu) failed: %v", err)
	}
	if newP.Name != "prod-eu" {
		t.Errorf("expected name to be prod-eu, got %s", newP.Name)
	}

	renamedCreds, err := v.GetCredentials("prod-eu")
	if err != nil {
		t.Fatalf("GetCredentials(prod-eu) failed: %v", err)
	}
	if renamedCreds == nil || renamedCreds.Password != "supersecretpassword" {
		t.Errorf("expected renamed profile to retain password, got %+v", renamedCreds)
	}

	// Delete profile
	if err := v.DeleteProfile("prod-eu"); err != nil {
		t.Fatalf("DeleteProfile failed: %v", err)
	}

	profiles, err := v.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles after deletion, got %d", len(profiles))
	}
}

func TestEncryptedExportAndImport(t *testing.T) {
	v1, dir1 := setupTestVault(t)
	pass := "VaultPass123!"
	if err := v1.Initialize(pass); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	p := models.NewSSHProfile("staging", "10.0.0.1", 2222, "deploy")
	p.AuthMethod = models.AuthMethodPassword
	_ = v1.SaveProfile(p)
	_ = v1.SetCredentials("staging", &models.ProfileCredentials{Password: "deploysecret"})

	exportFile := filepath.Join(dir1, "backup.sshm")
	exportPass := "ExportPassphrase999!"

	if err := v1.ExportVault(exportFile, exportPass); err != nil {
		t.Fatalf("ExportVault failed: %v", err)
	}

	// Verify export file is encrypted
	rawContent, err := os.ReadFile(exportFile)
	if err != nil {
		t.Fatalf("failed to read export file: %v", err)
	}
	if string(rawContent[:10]) != "SSHMEXPORT" {
		t.Fatalf("expected export file to start with SSHMEXPORT magic header")
	}

	// Setup a clean new second vault
	dir2 := t.TempDir()
	config.SetCustomConfigDir(dir2)
	v2, err := NewVault(NewMemoryKeyring())
	if err != nil {
		t.Fatalf("NewVault 2 failed: %v", err)
	}
	if err := v2.Initialize("NewVaultPass"); err != nil {
		t.Fatalf("Initialize 2 failed: %v", err)
	}

	// Import with wrong passphrase
	_, err = v2.ImportVault(exportFile, "wrong-export-pass", false)
	if err == nil {
		t.Fatalf("expected ImportVault to fail with wrong passphrase")
	}

	// Import with correct passphrase
	count, err := v2.ImportVault(exportFile, exportPass, false)
	if err != nil {
		t.Fatalf("ImportVault failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 profile imported, got %d", count)
	}

	importedP, err := v2.GetProfile("staging")
	if err != nil {
		t.Fatalf("GetProfile in v2 failed: %v", err)
	}
	if importedP.Host != "10.0.0.1" || importedP.Port != 2222 {
		t.Errorf("imported profile mismatch: %+v", importedP)
	}

	importedCreds, err := v2.GetCredentials("staging")
	if err != nil {
		t.Fatalf("GetCredentials in v2 failed: %v", err)
	}
	if importedCreds == nil || importedCreds.Password != "deploysecret" {
		t.Errorf("imported credentials mismatch: %+v", importedCreds)
	}
}
