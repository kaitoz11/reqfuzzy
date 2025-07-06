package crypto

import "crypto/sha256"

func HashSha256(plaintext string) string {
	h := sha256.New()
	h.Write([]byte(plaintext))
	return string(h.Sum(nil))
}
