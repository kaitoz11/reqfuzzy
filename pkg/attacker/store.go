package attacker

import (
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
)

type RequestStore struct {
	apiPath map[string]*RequestContext
}

func NewRequestStore() *RequestStore {
	return &RequestStore{
		apiPath: make(map[string]*RequestContext),
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

	// load request if not loaded
	if !rs.apiPath[name].IsLoaded {
		parsedRequest, err := rawreq.ParseRawRequestFromFile(rs.apiPath[name].filePath)
		if err != nil {
			return nil, err
		}
		rs.apiPath[name].ParsedRequest = parsedRequest
		rs.apiPath[name].IsLoaded = true
	}

	return rs.apiPath[name], nil
}

type RequestContext struct {
	filePath string
	IsLoaded bool

	ParsedRequest *rawreq.ParsedRawRequest
}
