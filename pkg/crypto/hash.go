package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HashSha256(plaintext string) string {
	h := sha256.New()
	h.Write([]byte(plaintext))
	return string(h.Sum(nil))
}

func Hmac(input, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(input))
	return string(h.Sum(nil))
}
