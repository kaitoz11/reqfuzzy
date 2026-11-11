package main

import (
	"log/slog"

	"github.com/kaitoz11/reqfuzzy/demo/api"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	me := api.NewBaseAPI()

	me.SendRequestWithModifer(api.LoginApi, func(request *attacker.Request) error {
		// request.UpdateJsonBody("header.client_info.platform", "Chrome 138.0.0.0, Windows NT 10.0, desktop hehehhe")
		return nil
	})
}
