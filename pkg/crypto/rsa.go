package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

func decryptWithOAEPOptions(privateKey *rsa.PrivateKey, ciphertextBase64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	opts := &rsa.OAEPOptions{
		Hash:    crypto.SHA256,
		MGFHash: crypto.SHA1,
		Label:   nil,
	}

	plaintext, err := privateKey.Decrypt(rand.Reader, ciphertext, opts)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	return plaintext, nil
}
