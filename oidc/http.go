package oidc

import (
	"net/http"
	"time"
)

type boundedTransport struct {
	base    http.RoundTripper
	maximum int64
	owned   bool
}

func (t boundedTransport) CloseIdleConnections() {
	if t.owned {
		if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}
func (t boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !httpsURL(request.URL.String(), true) {
		return nil, ErrUnavailable
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, ErrUnavailable
	}
	if response.Body == nil {
		response.Body = http.NoBody
	}
	if response.ContentLength > t.maximum {
		response.Body.Close()
		return nil, ErrUnavailable
	}
	response.Body = http.MaxBytesReader(nil, response.Body, t.maximum)
	return response, nil
}
func boundedClient(original *http.Client, timeout time.Duration, maximum int64) *http.Client {
	result := http.Client{}
	if original != nil {
		result = *original
	}
	if result.Timeout <= 0 || result.Timeout > timeout {
		result.Timeout = timeout
	}
	transport := result.Transport
	owned := false
	if transport == nil {
		transport = http.DefaultTransport
		if base, ok := transport.(*http.Transport); ok {
			clone := base.Clone()
			clone.MaxResponseHeaderBytes = 64 * 1024
			transport = clone
			owned = true
		}
	}
	result.Transport = boundedTransport{base: transport, maximum: maximum, owned: owned}
	previous := result.CheckRedirect
	result.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 0 && via[0].Method != "GET" {
			return http.ErrUseLastResponse
		}
		if len(via) >= 3 || !httpsURL(request.URL.String(), true) {
			return ErrUnavailable
		}
		if previous != nil {
			return previous(request, via)
		}
		return nil
	}
	return &result
}
