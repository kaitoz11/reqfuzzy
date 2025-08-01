package main

import (
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/test_project/api"
)

func main() {
	hacker := api.NewBaseApi()

	hacker.SendRequest(api.Login, func(request attacker.Request) error {
		return nil
	})

	hacker.SendRequest(api.Login)
}
