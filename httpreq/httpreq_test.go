package httpreq

import (
	"encoding/json"
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/miekg/dns"
	"github.com/saturncloud/cert-manager-webhook-httpreq/mock"
	"github.com/stretchr/testify/assert"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestHttpReqSolver_Name(t *testing.T) {
	solver := New()
	assert.Equal(t, "httpreq", solver.Name())
}

func TestHttpReqSolver_Initialize(t *testing.T) {
	solver := New()
	done := make(chan struct{})
	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Expected Initialize not to error")
	close(done)
}

func TestHttpReqSolver_Present_Cleanup(t *testing.T) {
	solver := New()
	done := make(chan struct{})
	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Expected Initialize not to error")

	mockEndpoint := mock.NewHTTPReqEndpoint()
	configData, err := json.Marshal(map[string]string{
		"endpoint": mockEndpoint.URL(),
	})
	assert.NoError(t, err, "Expected config marshalling not to error")

	validTestData := []struct {
		hostname string
		record   string
	}{
		{"test1.example.com.", "testkey1"},
		{"test2.example.com.", "testkey2"},
		{"test3.example.com.", "testkey3"},
	}
	for _, test := range validTestData {
		err := solver.Present(&acme.ChallengeRequest{
			Action:       acme.ChallengeActionPresent,
			Type:         "dns-01",
			ResolvedFQDN: test.hostname,
			Key:          test.record,
			Config:       &apiextensionsv1.JSON{Raw: configData},
		})
		assert.NoError(t, err, "Unexpected error while presenting %v", t)
	}

	// Resolve test data
	for _, test := range validTestData {
		msg := new(dns.Msg)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		msg.Question = make([]dns.Question, 1)
		msg.Question[0] = dns.Question{Name: dns.Fqdn(test.hostname), Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
		in, err := dns.Exchange(msg, mockEndpoint.DNS().Addr())

		assert.NoError(t, err, "Presented record %s not resolvable", test.hostname)
		assert.Len(t, in.Answer, 1, "RR response is of incorrect length")
		assert.Equal(t, []string{test.record}, in.Answer[0].(*dns.TXT).Txt, "TXT record returned did not match presented record")
	}

	// Cleanup test data
	for _, test := range validTestData {
		err := solver.CleanUp(&acme.ChallengeRequest{
			Action:       acme.ChallengeActionCleanUp,
			Type:         "dns-01",
			ResolvedFQDN: test.hostname,
			Key:          test.record,
			Config:       &apiextensionsv1.JSON{Raw: configData},
		})
		assert.NoError(t, err, "Unexpected error while cleaning up %v", t)
	}

	// Resolve test data post-cleanup
	for _, test := range validTestData {
		msg := new(dns.Msg)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		msg.Question = make([]dns.Question, 1)
		msg.Question[0] = dns.Question{Name: dns.Fqdn(test.hostname), Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
		in, err := dns.Exchange(msg, mockEndpoint.DNS().Addr())

		assert.NoError(t, err, "Presented record %s not resolvable", test.hostname)
		assert.Len(t, in.Answer, 0, "RR response is of incorrect length")
		assert.Equal(t, dns.RcodeNameError, in.Rcode, "Expexted NXDOMAIN")
	}

	close(done)
}
