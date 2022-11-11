package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

func Encrypt(message string, target *rsa.PublicKey) (string, error) {
	secretMessage := []byte(message)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, target, secretMessage, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(cipherText string, receiver *rsa.PrivateKey) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", nil
	}
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, receiver, ciphertext, nil)
	if err != nil {
		return "", nil
	}

	return string(plaintext), nil
}
