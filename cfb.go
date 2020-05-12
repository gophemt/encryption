package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func EncryptCFBString(text, key []byte) (string, error) {
	ciphertext, err := EncryptCFB(text, key)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptCFBString(data string, key []byte) (string, error) {
	cipherdata, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	ciphertext, err := DecryptCFB(cipherdata, key)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s", ciphertext), nil
}

func EncryptCFB(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func DecryptCFB(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(data, data)
	return data, nil
}
