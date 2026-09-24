package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// Vault magic header
	magicHeader = "SSHMVAULT"
	versionByte = byte(0x01)

	// Argon2id parameters
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	keyLen       = 32 // 256-bit AES key
	saltLen      = 16
	nonceLen     = 12
)

var (
	ErrInvalidCiphertext = errors.New("invalid or corrupted vault ciphertext")
	ErrWrongPassphrase   = errors.New("incorrect master passphrase or corrupted vault")
)

// DeriveKey derives a 256-bit AES key from a passphrase and a salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keyLen)
}

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto rand failure: %w", err)
	}
	return b, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the provided key.
// It packages: MagicHeader (9B) + Version (1B) + Salt (16B) + Nonce (12B) + Ciphertext + AuthTag (16B).
func Encrypt(plaintext, key, salt []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length %d, expected 32 bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce, err := GenerateRandomBytes(nonceLen)
	if err != nil {
		return nil, err
	}

	// Prepare additional authenticated data (AAD): Header + Version + Salt
	aad := append([]byte(magicHeader), versionByte)
	aad = append(aad, salt...)

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Result structure:
	// [Header: 9B][Version: 1B][Salt: 16B][Nonce: 12B][Ciphertext + Tag]
	out := make([]byte, 0, len(aad)+len(nonce)+len(ciphertext))
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func Decrypt(envelope, key []byte) ([]byte, error) {
	headerLen := len(magicHeader) + 1 + saltLen
	minLen := headerLen + nonceLen + 16 // 16 bytes auth tag minimum
	if len(envelope) < minLen {
		return nil, ErrInvalidCiphertext
	}

	// Verify magic header
	if subtle.ConstantTimeCompare(envelope[:len(magicHeader)], []byte(magicHeader)) != 1 {
		return nil, ErrInvalidCiphertext
	}

	if envelope[len(magicHeader)] != versionByte {
		return nil, fmt.Errorf("unsupported vault version: %d", envelope[len(magicHeader)])
	}

	aad := envelope[:headerLen]
	nonce := envelope[headerLen : headerLen+nonceLen]
	ciphertext := envelope[headerLen+nonceLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	return plaintext, nil
}

// ExtractSalt extracts the 16-byte salt from an encrypted envelope.
func ExtractSalt(envelope []byte) ([]byte, error) {
	headerLen := len(magicHeader) + 1
	if len(envelope) < headerLen+saltLen {
		return nil, ErrInvalidCiphertext
	}
	if subtle.ConstantTimeCompare(envelope[:len(magicHeader)], []byte(magicHeader)) != 1 {
		return nil, ErrInvalidCiphertext
	}
	salt := make([]byte, saltLen)
	copy(salt, envelope[headerLen:headerLen+saltLen])
	return salt, nil
}

// ZeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func ZeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
