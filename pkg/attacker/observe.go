package attacker

import (
	"context"
	"net/http"

	"github.com/imroc/req/v3"
)

// HTTPObserver runs at the actual HTTP RoundTrip boundary, after client middleware.
type HTTPObserver func(*http.Request, http.RoundTripper) (*http.Response, error)
type observerKey struct{}
type observedTransport struct{ next http.RoundTripper }

func (t *observedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	observer, _ := request.Context().Value(observerKey{}).(HTTPObserver)
	if observer == nil {
		return t.next.RoundTrip(request)
	}
	delegated := request.Clone(context.WithValue(request.Context(), observerKey{}, HTTPObserver(nil)))
	return observer(delegated, t.next)
}
func (t *observedTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func observeClient(client *req.Client) *req.Client {
	httpClient := client.GetClient()
	if _, ok := httpClient.Transport.(*observedTransport); !ok {
		next := httpClient.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		httpClient.Transport = &observedTransport{next: next}
	}
	return client
}
func (c *HClient) SendRequestObserved(request Request, observer HTTPObserver) (Response, error) {
	request.SetContext(context.WithValue(request.Context(), observerKey{}, observer))
	return c.SendRequest(request)
}
