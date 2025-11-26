package attacker

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
)

type FuzzingStatus int

const (
	FuzzingStatusNotStarted FuzzingStatus = iota
	FuzzingStatusRunning
	FuzzingStatusPaused
	FuzzingStatusDone
	FuzzingStatusError
)

type FuzzerClient struct {
	client  *HClient
	request Request

	modifier func(request Request) error

	injectors []func(request Request) error

	extractor func(response Response) string

	results []FuzzingResultEntry

	status FuzzingStatus
}

type FuzzingResultEntry struct {
	injector func(request Request) error
	Request  Request

	Response  Response
	Extracted string
	Done      bool
	Error     error
}

type FuzzerBuilder interface {
	AddInjector(injector func(request Request) error) FuzzerBuilder
	WithBaseModifiers(modifiers ...func(request Request) error) FuzzerBuilder
	Build() (Fuzzer, error)
}

type Fuzzer interface {
	Fuzz(...FuzzingOption) error
	PauseFuzzing()
	PrintFuzzingResult()
}

func NewFuzzerBuilder(
	client *HClient,
	request Request,
) FuzzerBuilder {
	return &FuzzerClient{
		client:    client,
		request:   request,
		modifier:  func(request Request) error { return nil },
		injectors: []func(request Request) error{},
		status:    FuzzingStatusNotStarted,
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
	return f
}

func (f *FuzzerClient) AddInjector(injector func(request Request) error) FuzzerBuilder {
	f.injectors = append(f.injectors, injector)
	return f
}

func (f *FuzzerClient) AddExtractor(extractor func(response Response) string) FuzzerBuilder {
	f.extractor = extractor
	return f
}

func (f *FuzzerClient) Build() (Fuzzer, error) {
	// TODO: validate the fuzzer
	if len(f.injectors) == 0 {
		return nil, errors.New("no injectors")
	}
	if f.extractor == nil {
		f.extractor = func(response Response) string { return "" }
	}

	f.results = make([]FuzzingResultEntry, 0, len(f.injectors))

	// build the fuzzer results
	for _, injector := range f.injectors {
		interceptedRequest := f.request.Copy(f.client.httpClient)
		f.modifier(interceptedRequest)
		injector(interceptedRequest)

		f.results = append(f.results, FuzzingResultEntry{
			injector: injector,
			Request:  interceptedRequest,
		})
	}
	return f, nil
}

type FuzzingConfig struct {
	RateLimiter time.Duration
}

type FuzzingOption func(config *FuzzingConfig)

func (f *FuzzerClient) startFuzzing(cfg *FuzzingConfig) {
	rateLimiter := cfg.RateLimiter

	timeTicker := time.Tick(rateLimiter)

	wg := new(sync.WaitGroup)

	f.status = FuzzingStatusRunning

	for i, r := range f.results {
		if r.Done {
			continue
		}

		if f.status == FuzzingStatusPaused {
			return
		}

		wg.Add(1)
		go func(i int, r FuzzingResultEntry) {
			defer wg.Done()
			res, err := f.client.SendRequest(r.Request)
			if err != nil {
				f.results[i].Done = false
				f.results[i].Error = err
				return
			}
			f.results[i].Response = res
			f.results[i].Done = true
			f.results[i].Extracted = f.extractor(res)
		}(i, r)

		<-timeTicker
	}

	wg.Wait()
	f.status = FuzzingStatusDone
}

func (f *FuzzerClient) Fuzz(opt ...FuzzingOption) error {
	cfg := &FuzzingConfig{
		RateLimiter: 2000 * time.Millisecond,
	}
	for _, o := range opt {
		o(cfg)
	}
	// fuzz the request
	f.startFuzzing(cfg)
	return nil
}

func (f *FuzzerClient) PauseFuzzing() {
	f.status = FuzzingStatusPaused
}

func (f *FuzzerClient) PrintFuzzingResult() {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleColoredBlackOnGreenWhite)
	t.AppendHeader(table.Row{"#", "status", "length", "Extracted", "Time"})
	for i, r := range f.results {
		if r.Done {
			t.AppendRow(table.Row{i, r.Response.Status, r.Response.ContentLength, r.Extracted, r.Response.TotalTime().String()})
		}
	}
	t.Render()
}
