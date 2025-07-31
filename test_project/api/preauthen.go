package api

import "github.com/kaitoz11/reqfuzzy/pkg/attacker"

const (
	Login ApiName = "Login"
)

func registerPreAuthen(apiStore *attacker.RequestStore) {
	apiStore.RegisterRequestFilePath(string(Login), "./path/to/rawrequest")
}
