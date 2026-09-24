package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alwin/sshm/internal/config"
	"github.com/alwin/sshm/internal/logging"
	"github.com/alwin/sshm/internal/vault"
	"github.com/alwin/sshm/pkg/models"
)

func TestSecurity_SecretsNotInListOrJSON(t *testing.T) {
	tempDir := t.TempDir()
	config.SetCustomConfigDir(tempDir)

	v, err := vault.NewVault(vault.NewMemoryKeyring())
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	if err := v.Initialize("MasterVaultPassphrase!"); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	secretPassword := "SuperSensitivePassword999!"
	secretKeyData := []byte("-----BEGIN PRIVATE KEY-----\nSecretKeyMaterial\n-----END PRIVATE KEY-----")
	secretPassphrase := "PrivateKeyPassphrase888!"

	p := models.NewSSHProfile("production", "203.0.113.10", 22, "ubuntu")
	p.AuthMethod = models.AuthMethodPassword

	if err := v.SaveProfile(p); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}

	creds := &models.ProfileCredentials{
		Password:   secretPassword,
		PrivateKey: secretKeyData,
		Passphrase: secretPassphrase,
	}
	if err := v.SetCredentials("production", creds); err != nil {
		t.Fatalf("SetCredentials failed: %v", err)
	}

	// 1. Check ListProfiles() output
	profiles, err := v.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}

	// 2. Check JSON serialization of profiles
	jsonData, err := json.Marshal(profiles)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(jsonData)

	// Ensure NONE of the secrets appear in profiles or JSON serialization
	if strings.Contains(jsonStr, secretPassword) {
		t.Fatalf("SECURITY VIOLATION: password leaked in JSON output: %s", jsonStr)
	}
	if strings.Contains(jsonStr, secretPassphrase) {
		t.Fatalf("SECURITY VIOLATION: passphrase leaked in JSON output: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "SecretKeyMaterial") {
		t.Fatalf("SECURITY VIOLATION: private key leaked in JSON output: %s", jsonStr)
	}

	// 3. Inspect metadata file profiles.json directly on disk
	profilesFilePath := filepath.Join(tempDir, "profiles.json")
	rawProfilesFile, err := os.ReadFile(profilesFilePath)
	if err != nil {
		t.Fatalf("failed to read profiles.json: %v", err)
	}
	rawProfilesStr := string(rawProfilesFile)

	if strings.Contains(rawProfilesStr, secretPassword) ||
		strings.Contains(rawProfilesStr, secretPassphrase) ||
		strings.Contains(rawProfilesStr, "SecretKeyMaterial") {
		t.Fatalf("SECURITY VIOLATION: plaintext secret found in profiles.json file!")
	}
}

func TestSecurity_VaultFileEncrypted(t *testing.T) {
	tempDir := t.TempDir()
	config.SetCustomConfigDir(tempDir)

	v, err := vault.NewVault(vault.NewMemoryKeyring())
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	masterPass := "StrongMasterPassword123!"
	if err := v.Initialize(masterPass); err != nil {
		t.Fatalf("failed to initialize vault: %v", err)
	}

	secretWord := "TopSecretPasswordThatMustNotBePlaintext"
	creds := &models.ProfileCredentials{Password: secretWord}
	if err := v.SetCredentials("server1", creds); err != nil {
		t.Fatalf("failed to save credentials: %v", err)
	}

	vaultFile := filepath.Join(tempDir, "vault.enc")
	vaultBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("failed to read vault.enc: %v", err)
	}

	// Verify vault is not plaintext
	if strings.Contains(string(vaultBytes), secretWord) {
		t.Fatalf("SECURITY VIOLATION: raw secret password found in plaintext inside vault.enc!")
	}
	if strings.Contains(string(vaultBytes), masterPass) {
		t.Fatalf("SECURITY VIOLATION: master passphrase found in plaintext inside vault.enc!")
	}

	// Verify magic header is present
	if string(vaultBytes[:9]) != "SSHMVAULT" {
		t.Fatalf("expected vault.enc to have SSHMVAULT magic header")
	}
}

func TestSecurity_LoggingRedaction(t *testing.T) {
	var buf bytes.Buffer
	logging.SetOutput(&buf)
	logging.SetDebug(true)

	secretPass := "mypassword12345"
	secretKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAABBBBBCCCCCDDDDD\n-----END OPENSSH PRIVATE KEY-----"

	logging.Debugf("User connected with password: %s", secretPass)
	logging.Debugf("Loaded key: %s", secretKey)

	logged := buf.String()

	if strings.Contains(logged, secretPass) {
		t.Fatalf("SECURITY VIOLATION: password leaked in debug logs: %s", logged)
	}
	if strings.Contains(logged, "AAAAABBBBBCCCCCDDDDD") {
		t.Fatalf("SECURITY VIOLATION: private key leaked in debug logs: %s", logged)
	}
}

func TestSecurity_ErrorRedaction(t *testing.T) {
	p := models.NewSSHProfile("prod-server", "10.0.0.1", 22, "admin")
	err := models.NewAuthFailedError(p, nil)

	errString := err.Error()

	// Ensure error never includes passwords, tokens, or credential values
	if strings.Contains(errString, "password=") || strings.Contains(errString, "secret123") {
		t.Fatalf("Unexpected secret field in error: %s", errString)
	}
}
