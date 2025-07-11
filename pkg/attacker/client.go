package attacker

import (
	"github.com/imroc/req/v3"
)

const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

type HClient struct {
	httpClient  *req.Client
	contextData map[string]string
	user        *Actor
}

func NewHClient() *HClient {
	return &HClient{
		httpClient: req.C().
			SetRedirectPolicy(req.NoRedirectPolicy()).
			SetUserAgent(DefaultUserAgent),
		contextData: make(map[string]string),
	}
}

func NewHClientWith(client *req.Client) *HClient {
	return &HClient{
		httpClient: client.
			SetRedirectPolicy(req.NoRedirectPolicy()).
			SetUserAgent(DefaultUserAgent),
		contextData: make(map[string]string),
	}
}

func (c *HClient) SetUser(user *Actor) {
	c.user = user
}

func (c *HClient) UseProxy(url, certfile string) {
	// TODO: check if the URL is valid
	c.httpClient.SetProxyURL(url)

	// TODO: check if the certfile is valid
	c.httpClient.SetRootCertsFromFile(certfile)
}

// X-Pwnfox-Color
func (c *HClient) UseColor(color ProxyColor) {
	c.httpClient.SetCommonHeaderNonCanonical("X-Pwnfox-Color", string(color))
}

func (c *HClient) WithUpdatedClient(updateClientCallback func(client *req.Client)) {
	updateClientCallback(c.httpClient)
}

func (c *HClient) UseBaseURL(baseURL string) {
	c.httpClient.SetBaseURL(baseURL)
}

func (c *HClient) SendRequest(r Request) (Response, error) {
	baseURL := c.httpClient.BaseURL
	response, err := r.Send(r.Method, baseURL+r.RawURL)
	if err != nil {
		return Response{nil}, err
	}
	return Response{response}, nil
}

func (c *HClient) SendRequestWithBaseURL(r Request, baseURL string) (Response, error) {
	response, err := r.Send(r.Method, baseURL+r.RawURL)
	if err != nil {
		return Response{nil}, err
	}
	return Response{response}, nil
}

func (c *HClient) ParseRawRequest(rawRequest string) (Request, error) {
	request, err := ParseRawRequest(c.httpClient, rawRequest)
	if err != nil {
		return Request{nil}, err
	}
	return Request{request}, nil
}
