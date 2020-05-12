package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

func EncryptGCMString(text []byte, key []byte) (string, error) {
	ciphertext, err := EncryptGCM(text, key)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptGCMString(data string, key []byte) (string, error) {
	cipherdata, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	ciphertext, err := DecryptGCM(cipherdata, key)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s", ciphertext), nil
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func EncryptGCM(data, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(string(key))))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func DecryptGCM(data, passphrase []byte) ([]byte, error) {
	key := []byte(createHash(string(passphrase)))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
