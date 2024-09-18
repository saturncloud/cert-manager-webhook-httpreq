// Package httpreq implements cert-manager webhook as an HTTP request to an external server
// based on the lego httpreq solver https://go-acme.github.io/lego/dns/httpreq/
package httpreq

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	// authorizationHeaderVal is a default header value for authorization. Useful in cases where there is only ever one
	// httpReq issuer so it doesn't need RBAC access to secrets. May be overridden by issuer config's header secret.
	authorizationHeader = os.Getenv("HTTPREQ_AUTH_HEADER")
	// authorizationHeaderName is the name for the default authorization header
	authorizationHeaderName = getEnvWithDefault("HTTPREQ_AUTH_HEADER_NAME", "Authorization")
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

func (hrs *httpReqSolver) Present(ch *acme.ChallengeRequest) error {
	ch.Action = acme.ChallengeActionPresent
	return hrs.challengeRequest(ch)
}

func (hrs *httpReqSolver) CleanUp(ch *acme.ChallengeRequest) error {
	ch.Action = acme.ChallengeActionCleanUp
	return hrs.challengeRequest(ch)
}

func (hrs *httpReqSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	if kubeClientConfig == nil {
		return nil
	}

	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	hrs.clientset = clientset
	return nil
}

func (hrs *httpReqSolver) challengeRequest(ch *acme.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	url, err := cfg.GetURL(ch.Action)
	if err != nil {
		return err
	}

	headers := hrs.headers.Clone()
	if cfg.HeaderSecretRef.Name != "" {
		if hrs.clientset == nil {
			return errors.New("unable to retrieve headers secret, kube client was not configured")
		}

		namespace := cfg.HeaderSecretRef.Namespace
		if namespace == "" {
			namespace = ch.ResourceNamespace
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		headerSecret, err := hrs.clientset.CoreV1().Secrets(namespace).Get(ctx, cfg.HeaderSecretRef.Name, v1.GetOptions{})
		if err != nil {
			return err
		}
		for key, b64 := range headerSecret.Data {
			val, err := base64.StdEncoding.DecodeString(string(b64))
			if err != nil {
				return err
			}
			headers[key] = []string{string(val)}
		}
	}

	body := ChallengeBody{Fqdn: ch.ResolvedFQDN, Value: ch.Key}
	var buffer bytes.Buffer
	json.NewEncoder(&buffer).Encode(body)

	request, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		return err
	}
	request.Header = headers

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected server response: %s", resp.Status)
	}
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (cfg IssuerConfig, err error) {
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func getEnvWithDefault(name, defaultVal string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return defaultVal
}
