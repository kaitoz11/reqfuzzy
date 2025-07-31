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

// SendRequest sends a request with modifiers.
// modifiers are executed in order to modify the request before sending it
func (a *Api[T]) SendRequest(apiName T, modifiers ...func(request attacker.Request) error) (attacker.Response, error) {
	reqContext, err := a.ApiStore.GetRequestContext(string(apiName))
	if err != nil {
		return attacker.Response{}, err
	}

	m := func(request attacker.Request) error {
		for _, modifier := range modifiers {
			if err := modifier(request); err != nil {
				return err
			}
		}
		return nil
	}

	return a.Client.SendRequestFromStore(reqContext, m)
}
