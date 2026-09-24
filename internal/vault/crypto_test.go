package vault

import (
	"bytes"
	"testing"
)

func TestCryptoRoundtrip(t *testing.T) {
	passphrase := "CorrectHorseBatteryStaple123!"
	salt, err := GenerateRandomBytes(saltLen)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	key := DeriveKey(passphrase, salt)
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	plaintext := []byte("secret ssh password or private key content")

	envelope, err := Encrypt(plaintext, key, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with correct key
	decrypted, err := Decrypt(envelope, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted %q does not match original %q", string(decrypted), string(plaintext))
	}

	// Test extracting salt
	extractedSalt, err := ExtractSalt(envelope)
	if err != nil {
		t.Fatalf("ExtractSalt failed: %v", err)
	}
	if !bytes.Equal(salt, extractedSalt) {
		t.Fatalf("extracted salt does not match original salt")
	}

	// Test wrong key/passphrase rejection
	wrongKey := DeriveKey("WrongPassphrase", salt)
	_, err = Decrypt(envelope, wrongKey)
	if err == nil {
		t.Fatalf("expected Decrypt to fail with wrong passphrase, but it succeeded")
	}

	// Test tampered ciphertext rejection
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-1] ^= 0xFF // Flip last bit of auth tag

	_, err = Decrypt(tampered, key)
	if err == nil {
		t.Fatalf("expected Decrypt to fail on tampered ciphertext, but it succeeded")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, val := range b {
		if val != 0 {
			t.Errorf("byte at index %d was not zeroed: %d", i, val)
		}
	}
}
