package mocking

import "math/rand"

func RandomString(charPool string, length int) string {
	result := make([]byte, length)

	for i := range result {
		result[i] = charPool[rand.Int()%len(charPool)]
	}
	return string(result)
}
