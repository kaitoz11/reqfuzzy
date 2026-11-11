package api

import (
	"github.com/imroc/req/v3"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

type ApiName string

type BaseAPI struct {
	Client *attacker.HClient

	apiStore *attacker.RequestStore
}

func NewBaseAPI() *BaseAPI {
	client := attacker.NewHClientWith(
		req.C().
			SetCommonHeaderNonCanonical("Tl-Tool", "true").
			SetCommonContentType("application/x-www-form-urlencoded; charset=UTF-8"))
	client.UseBaseURL("https://example.invalid")

	apiStore := attacker.NewRequestStore()
	// PreAuthen
	// apiStore.RegisterRequestFilePath(string(LoginApi), "./raw/preauthen/login.txt")
	registerPreAuthen(apiStore)

	return &BaseAPI{
		Client:   client,
		apiStore: apiStore,
	}
}

func (b *BaseAPI) SendRequest(apiName ApiName) (attacker.Response, error) {
	return b.SendRequestWithModifer(apiName, func(request *attacker.Request) error {
		return nil
	})
}

func (b *BaseAPI) SendRequestWithModifer(apiName ApiName, modifier func(request *attacker.Request) error) (attacker.Response, error) {
	requestContext, err := b.apiStore.GetRequestContext(string(apiName))
	if err != nil {
		return attacker.Response{}, err
	}

	return b.Client.SendRequestFromStore(requestContext, modifier)
}
