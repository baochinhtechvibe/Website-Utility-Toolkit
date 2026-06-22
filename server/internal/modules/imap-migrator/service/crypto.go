package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

// getSecretKey retrieves a 32-byte key from APP_SECRET_KEY.
// The key must be a base64 encoded 32-byte string.
// If the key is not set or invalid, it panics to prevent starting insecurely.
func getSecretKey() []byte {
	keyBase64 := os.Getenv("APP_SECRET_KEY")
	if keyBase64 == "" {
		log.Fatal().Msg("APP_SECRET_KEY is not set in environment! Refusing to start insecurely.")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		log.Fatal().Err(err).Msg("APP_SECRET_KEY must be a valid base64 encoded string")
	}

	if len(keyBytes) != 32 {
		log.Fatal().Int("length", len(keyBytes)).Msg("APP_SECRET_KEY must be exactly 32 bytes after base64 decoding")
	}

	return keyBytes
}

// EncryptAES encrypts plaintext using AES-256-GCM and returns a base64 encoded string.
func EncryptAES(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(getSecretKey())
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return base64 to store easily in SQLite TEXT field
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts a base64 encoded AES-256-GCM ciphertext.
func DecryptAES(encryptedBase64 string) (string, error) {
	if encryptedBase64 == "" {
		return "", nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(getSecretKey())
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
