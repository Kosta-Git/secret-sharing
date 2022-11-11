package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)
import "crypto/rand"

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

type KeyAndNonce struct {
	key   []byte
	nonce []byte
}

func NewKey(formatted string) (*KeyAndNonce, error) {
	elements := strings.Split(formatted, ";")
	if len(elements) != 2 {
		return nil, errors.New("Unable to parse formatted key")
	}

	key, err := base64.RawStdEncoding.DecodeString(elements[0])
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(elements[1])
	if err != nil {
		return nil, err
	}

	return &KeyAndNonce{key: key, nonce: nonce}, nil
}

func (k KeyAndNonce) Format() string {
	key := base64.RawStdEncoding.EncodeToString(k.key)
	nonce := base64.RawStdEncoding.EncodeToString(k.nonce)

	return fmt.Sprintf("%v;%v", key, nonce)
}

func (k KeyAndNonce) FormatBytes() []byte {
	return []byte(k.Format())
}

func GenerateSecret(keySize int, nonceSize int) (*KeyAndNonce, error) {
	switch keySize {
	case 16, 24, 32:
		break
	default:
		return nil, KeySizeError(keySize)
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &KeyAndNonce{key: key, nonce: nonce}, nil
}

func Encrypt(message string, secret *KeyAndNonce) (string, error) {
	cipher, err := createBlockCipher(secret.key)
	if err != nil {
		return "", err
	}

	ciphertext := cipher.Seal(nil, secret.nonce, []byte(message), nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(message string, secret *KeyAndNonce) (string, error) {
	messageBytes, err := base64.RawStdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}

	cipher, err := createBlockCipher(secret.key)
	if err != nil {
		return "", err
	}

	ciphertext, err := cipher.Open(nil, secret.nonce, messageBytes, nil)
	if err != nil {
		return "", err
	}
	return string(ciphertext), nil
}

func createBlockCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesGCM, nil
}
