package aes

import (
	"testing"
)

func TestEncryptDecryptRoutine(t *testing.T) {
	secret, err := GenerateSecret(32, 12)
	payload := "hello"
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}
	cipher, err := Encrypt(payload, secret)
	if err != nil {
		t.Fatalf("Unable to encrypt payload: %v", err)
	}
	decipher, err := Decrypt(cipher, secret)
	if err != nil {
		t.Fatalf("Unable to decrypt payload: %v", err)
	}

	if decipher != payload {
		t.Fatalf("Expected: %v, Got: %v", payload, decipher)
	}
}
