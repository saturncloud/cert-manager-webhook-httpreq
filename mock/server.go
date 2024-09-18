package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// NewHttpReqEndpoint creates a test httpreq endpoint and DNS server
func NewHttpReqEndpoint() *HttpReqEndpoint {
	mock := &HttpReqEndpoint{}
	mock.server = httptest.NewServer(mock)
	mock.dns = NewMockDNS()
	mock.dns.Run()
	return mock
}

// HttpReqEndpoint is a test httpreq endpoint that creates and deletes DNS records in a test DNS server
type HttpReqEndpoint struct {
	server *httptest.Server
	dns    *DNS
}

func (hre *HttpReqEndpoint) URL() string {
	return hre.server.URL
}

func (hre *HttpReqEndpoint) DNS() *DNS {
	return hre.dns
}

func (hre *HttpReqEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (hre *HttpReqEndpoint) Close() {
	hre.dns.Close()
	hre.server.Close()
}
