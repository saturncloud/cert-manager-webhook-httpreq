package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"github.com/stretchr/testify/assert"

	"github.com/saturncloud/cert-manager-webhook-httpreq/httpreq"
	"github.com/saturncloud/cert-manager-webhook-httpreq/mock"
)

var (
	zone       = getEnvWithDefault("TEST_ZONE_NAME", "example.com.")
	configFile = getEnvWithDefault("TEST_CONFIG_FILE", "testdata/httpreq/config.json")
)

func TestRunsSuite(t *testing.T) {
	issuerConfig, err := loadIssuerConfig(configFile)
	assert.NoError(t, err, "Exected no error from loading issuer config")

	acmeOptions := []acmetest.Option{
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
	}
	if issuerConfig.Endpoint == "" {
		mockEndpoint := mock.NewHttpReqEndpoint()
		defer mockEndpoint.Close()

		acmeOptions = append(
			acmeOptions,
			acmetest.SetDNSServer(mockEndpoint.DNS().Addr()),
			acmetest.SetUseAuthoritative(false),
			acmetest.SetPropagationLimit(5*time.Second),
			acmetest.SetPollInterval(200*time.Millisecond),
		)
		issuerConfig = httpreq.IssuerConfig{
			Endpoint: mockEndpoint.URL(),
		}
	}
	acmeOptions = append(acmeOptions, acmetest.SetConfig(issuerConfig))

	fixture := acmetest.NewFixture(httpreq.New(), acmeOptions...)

	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

func loadIssuerConfig(file string) (issuerConfig httpreq.IssuerConfig, err error) {
	f, err := os.Open(file)
	if err != nil {
		return issuerConfig, err
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(&issuerConfig)
	return issuerConfig, err
}

func getEnvWithDefault(name, defaultVal string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return defaultVal
}
