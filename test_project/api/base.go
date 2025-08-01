package api

import (
	"github.com/imroc/req/v3"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/base"
)

type ApiName string

type BaseApi struct {
	*base.Api[ApiName]
}

func NewBaseApi() *BaseApi {
	client := attacker.NewHClientWith(
		req.C(),
	)
	client.UseBaseURL("https://example.com")
	// client.UseProxy("http://127.0.0.1:8080", "./path/to/cert")

	apiStore := attacker.NewRequestStore(
		attacker.BlackListPwnfoxHeader,
	)

	registerPreAuthen(apiStore)

	baseApi := base.NewApi[ApiName](client, apiStore)

	return &BaseApi{baseApi}
}
