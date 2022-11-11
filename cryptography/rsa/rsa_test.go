package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestEncryptDecryptRoutine(t *testing.T) {
	rng := rand.Reader
	payload := "hello"
	key, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Fatalf("Unable to create key: %v", err)
	}
	cipher, err := Encrypt(payload, &key.PublicKey)
	if err != nil {
		t.Fatalf("Unable to encrypt payload: %v", err)
	}
	decipher, err := Decrypt(cipher, key)
	if err != nil {
		t.Fatalf("Unable to decrypt payload: %v", err)
	}

	if decipher != payload {
		t.Fatalf("Expected: %v, Got: %v", payload, decipher)
	}
}
