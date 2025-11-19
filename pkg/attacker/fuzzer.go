package attacker

import "fmt"

type FuzzerClient struct {
	client  *HClient
	request Request

	modifier func(request Request) error

	injectors []func(request Request) error
}

type FuzzerBuilder interface {
	AddInjector(injector func(request Request) error) FuzzerBuilder
	WithBaseModifiers(modifiers ...func(request Request) error) FuzzerBuilder
	Build() Fuzzer
}

type Fuzzer interface {
	Fuzz() error
}

func NewFuzzerBuilder(
	client *HClient,
	request Request,
) FuzzerBuilder {
	fmt.Println("NewFuzzerBuilder")
	return &FuzzerClient{
		client:    client,
		request:   request,
		modifier:  func(request Request) error { return nil },
		injectors: []func(request Request) error{},
	}
}

func (f *FuzzerClient) WithBaseModifiers(modifiers ...func(request Request) error) FuzzerBuilder {
	f.modifier = func(request Request) error {
		for _, modifier := range modifiers {
			if err := modifier(request); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Println("modifier")
	return f
}

func (f *FuzzerClient) AddInjector(injector func(request Request) error) FuzzerBuilder {
	f.injectors = append(f.injectors, injector)
	return f
}

func (f *FuzzerClient) Build() Fuzzer {
	// TODO: validate the fuzzer
	return f
}

func (f *FuzzerClient) Fuzz() error {
	// parse the request

	// fuzz the request
	for _, injector := range f.injectors {
		fmt.Println("i")
		interceptedRequest := f.request

		f.modifier(interceptedRequest)
		injector(interceptedRequest)
		_, err := f.client.SendRequest(interceptedRequest)
		if err != nil {
			fmt.Println("err")
			return err
		}
	}
	return nil
}
