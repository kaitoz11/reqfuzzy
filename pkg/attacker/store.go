package attacker

import (
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
)

type RequestContext struct {
	filePath string
	IsLoaded bool

	ParsedRequest *rawreq.ParsedRawRequest
}

type RequestStore struct {
	apiPath map[string]*RequestContext

	// Parsing raw request options
	options rawreq.Options
}

func BlackListPwnfoxHeader(options rawreq.Options) rawreq.Options {
	options.BlacklistedHeaders.Add(PwnFoxHeaderKeyColor)
	return options
}

func NewRequestStore(opts ...func(options rawreq.Options) rawreq.Options) *RequestStore {
	option := rawreq.NewOptions()

	for _, opt := range opts {
		option = opt(option)
	}

	return &RequestStore{
		apiPath: make(map[string]*RequestContext),
		options: option,
	}
}

func (rs *RequestStore) RegisterRequestFilePath(name string, filePath string) {
	rs.apiPath[name] = &RequestContext{
		filePath: filePath,
		IsLoaded: false,

		ParsedRequest: nil,
	}
}

func (rs *RequestStore) GetRequestContext(name string) (*RequestContext, error) {
	if _, exists := rs.apiPath[name]; !exists {
		return nil, fmt.Errorf("request %s not found from store", name)
	}

	// only load request if not loaded
	if !rs.apiPath[name].IsLoaded {
		parsedRequest, err := rawreq.ParseRawRequestFromFile(rs.apiPath[name].filePath, rs.options)
		if err != nil {
			return nil, err
		}
		rs.apiPath[name].ParsedRequest = parsedRequest
		rs.apiPath[name].IsLoaded = true
	}

	return rs.apiPath[name], nil
}
