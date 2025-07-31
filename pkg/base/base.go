package base

import "github.com/kaitoz11/reqfuzzy/pkg/attacker"

type Api[T ~string] struct {
	Client *attacker.HClient

	ApiStore *attacker.RequestStore
}

func NewApi[T ~string](client *attacker.HClient, apiStore *attacker.RequestStore) *Api[T] {
	return &Api[T]{
		Client:   client,
		ApiStore: apiStore,
	}
}

func (a *Api[T]) SendRequestWithModifer(apiName T, modifier func(request attacker.Request) error) (attacker.Response, error) {
	reqContext, err := a.ApiStore.GetRequestContext(string(apiName))
	if err != nil {
		return attacker.Response{}, err
	}

	return a.Client.SendRequestFromStore(reqContext, modifier)
}

func (a *Api[T]) SendRequest(apiName T) (attacker.Response, error) {
	return a.SendRequestWithModifer(apiName, func(request attacker.Request) error {
		return nil
	})
}
