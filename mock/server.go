// Package mock provides testing utilities for mocking an HTTPReq endpoint and DNS server
package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// NewHTTPReqEndpoint creates a test httpreq endpoint and DNS server
func NewHTTPReqEndpoint() *HTTPReqEndpoint {
	mock := &HTTPReqEndpoint{}
	mock.server = httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	mock.dns = NewMockDNS()
	mock.dns.Run()
	return mock
}

// HTTPReqEndpoint is a test httpreq endpoint that creates and deletes DNS records in a test DNS server
type HTTPReqEndpoint struct {
	server *httptest.Server
	dns    *DNS
}

// URL returns the HTTP URL of the mock httpreq endpoint
func (hre *HTTPReqEndpoint) URL() string {
	return hre.server.URL
}

// DNS returns the mock DNS server for the httpreq endpoint
func (hre *HTTPReqEndpoint) DNS() *DNS {
	return hre.dns
}

func (hre *HTTPReqEndpoint) serveHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch r.URL.Path {
	case "/present":
		hre.dns.Present(body["fqdn"], body["value"])
	case "/cleanup":
		hre.dns.Cleanup(body["fqdn"])
	}
	w.WriteHeader(http.StatusNoContent)
}

// Close stops the test endpoint and DNS servers
func (hre *HTTPReqEndpoint) Close() {
	hre.dns.Close()
	hre.server.Close()
}
