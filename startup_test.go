package main

import (
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	"github.com/stretchr/testify/require"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/saturncloud/cert-manager-webhook-httpreq/httpreq"
)

// TestChallengeServerStarts builds the solver API server the way cmd.RunWebhookServer does at
// startup. A k8s.io/apiserver version that does not match the one cert-manager generated its
// OpenAPI definitions for fails here ("cannot find model definition for ...TypeMeta"); the
// conformance suite in main_test.go never builds this server, so it passes on a webhook that
// crashes on start.
func TestChallengeServerStarts(t *testing.T) {
	genericConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	genericConfig.ExternalAddress = "192.168.10.4:443"
	genericConfig.LoopbackClientConfig = &rest.Config{}

	cfg := apiserver.Config{
		GenericConfig: genericConfig,
		ExtraConfig: apiserver.ExtraConfig{
			SolverGroup: "acme.example.com",
			Solvers:     []webhook.Solver{httpreq.New()},
		},
	}
	_, err := cfg.Complete().New()
	require.NoError(t, err)
}
