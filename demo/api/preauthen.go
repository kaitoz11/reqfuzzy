package api

import "github.com/kaitoz11/reqfuzzy/pkg/attacker"

const (
	LoginApi ApiName = "LoginAPI"
)

func registerPreAuthen(apiStore *attacker.RequestStore) {
	// PreAuthen
	apiStore.RegisterRequestFilePath(string(LoginApi), "./raw/preauthen/login.txt")
}
