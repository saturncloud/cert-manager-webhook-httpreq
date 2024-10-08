// Package httpreq implements cert-manager webhook as an HTTP request to an external server
// based on the lego httpreq solver https://go-acme.github.io/lego/dns/httpreq/
package httpreq

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	// authorizationHeader is a default header value for authorization. Useful in cases where there is only ever one
	// httpReq issuer so it doesn't need RBAC access to secrets. May be overridden by issuer config's header secret.
	authorizationHeader = os.Getenv("HTTPREQ_AUTH_HEADER")
	// authorizationHeaderName is the name for the default authorization header
	authorizationHeaderName = getEnvWithDefault("HTTPREQ_AUTH_HEADER_NAME", "Authorization")

	logger = logf.FromContext(context.Background(), "httpreq-webhook")
)

// ChallengeBody is the format for data sent to the remote server
type ChallengeBody struct {
	Fqdn  string `json:"fqdn"`
	Value string `json:"value"`
}

// IssuerConfig is data set on the kubernetes webhook issuer to configure httpreq
type IssuerConfig struct {
	// Endpoint is the base URL of the remote server
	Endpoint string `json:"endpoint"`
	// PresentPath is the path for presenting a new challenge record. Defaults to "/present"
	PresentPath string `json:"presentPath"`
	// CleanupPAth is the path for deleting previous challenge records. Defaults to "/cleanup"
	CleanupPath string `json:"cleanupPath"`
	// HeaderSecretRef is a reference to a kubernetes Secret with HTTP headers to add to challenge requests
	HeaderSecretRef struct{ Name, Namespace string } `json:"headerSecretRef"`
}

// GetURL formats the endpoint URL for a given action
func (ic IssuerConfig) GetURL(action acme.ChallengeAction) (string, error) {
	var path string
	switch action {
	case acme.ChallengeActionPresent:
		if ic.PresentPath == "" {
			path = "/present"
		} else {
			path = ic.PresentPath
		}
	case acme.ChallengeActionCleanUp:
		if ic.CleanupPath == "" {
			path = "/cleanup"
		} else {
			path = ic.CleanupPath
		}
	default:
		return "", fmt.Errorf("unrecognized challenge action: %s", action)
	}

	url, err := url.JoinPath(ic.Endpoint, path)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint: %s", err)
	}
	return url, nil
}

// New creates an httpreq solver and returns it as a cert-manager webook Solver interface
func New() webhook.Solver {
	solver := &httpReqSolver{name: "httpreq", headers: http.Header{}}
	if authorizationHeader != "" {
		solver.headers[authorizationHeaderName] = []string{authorizationHeader}
	}
	return solver
}

// httpReqSolver implements the cert-manager webhook issuer as an HTTP client
// that sends requests to a remote server.
type httpReqSolver struct {
	name      string
	headers   http.Header
	clientset *kubernetes.Clientset
}

func (hrs *httpReqSolver) Name() string {
	return hrs.name
}

func (hrs *httpReqSolver) Present(ch *acme.ChallengeRequest) (err error) {
	logger.Info("Present challenge", "fqdn", ch.ResolvedFQDN, "uid", ch.UID)
	ch.Action = acme.ChallengeActionPresent
	if err = hrs.challengeRequest(ch); err != nil {
		logger.Error(err, "Present failed", "fqdn", ch.ResolvedFQDN, "uid", ch.UID)
	}
	return err
}

func (hrs *httpReqSolver) CleanUp(ch *acme.ChallengeRequest) (err error) {
	logger.Info("Cleanup challenge", "fqdn", ch.ResolvedFQDN, "uid", ch.UID)
	ch.Action = acme.ChallengeActionCleanUp
	if err = hrs.challengeRequest(ch); err != nil {
		logger.Error(err, "Cleanup failed", "fqdn", ch.ResolvedFQDN, "uid", ch.UID)
	}
	return err
}

func (hrs *httpReqSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	if kubeClientConfig == nil {
		logger.Info("Skipping kubernetes client config")
		return nil
	}

	logger.V(logf.InfoLevel).Info("Configuring kubernetes client")
	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("kubernetes client config failed: %s", err)
	}

	hrs.clientset = clientset
	return nil
}

func (hrs *httpReqSolver) challengeRequest(ch *acme.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	url, err := cfg.GetURL(ch.Action)
	if err != nil {
		return fmt.Errorf("unable to parse httpreq url: %s", err)
	}

	headers := hrs.headers.Clone()
	if cfg.HeaderSecretRef.Name != "" {
		if hrs.clientset == nil {
			return errors.New("unable to retrieve headers secret, kube client was not configured")
		}

		name := cfg.HeaderSecretRef.Name
		namespace := cfg.HeaderSecretRef.Namespace
		if namespace == "" {
			namespace = ch.ResourceNamespace
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		headerSecret, err := hrs.clientset.CoreV1().Secrets(namespace).Get(ctx, name, v1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to read header secret %s/%s: %s", namespace, name, err)
		}
		for key, val := range headerSecret.Data {
			headers[key] = []string{string(val)}
		}
	}

	body := ChallengeBody{Fqdn: ch.ResolvedFQDN, Value: ch.Key}
	var buffer bytes.Buffer
	if err = json.NewEncoder(&buffer).Encode(body); err != nil {
		return fmt.Errorf("encoding challenge body failed: %s", err)
	}

	request, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		return fmt.Errorf("invalid request: %s", err)
	}
	request.Header = headers

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request to httpreq endpoint failed: %s", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected httpreq endpoint response: %s", resp.Status)
	}
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (cfg IssuerConfig, err error) {
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func getEnvWithDefault(name, defaultVal string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return defaultVal
}
