package traefik_keycloak_auth

// HTTP client used to talk to the authorization server.
//
// It implements the clientConfig section of the reference:
//   - clientConfig.timeoutSeconds bounds a whole request;
//   - clientConfig.maxRetries retries a request that failed;
//   - clientConfig.tls.ca / .cert / .key / .insecureSkipVerify configure the
//     transport TLS (custom CA bundle and client certificate for mTLS).
//
// The retries are implemented at the call sites through doWithRetries rather
// than with a custom http.RoundTripper: yaegi 0.16.1 (the interpreter Traefik
// uses to load a plugin) cannot assign an interpreted type to the stdlib
// interface field http.Client.Transport.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
)

const defaultClientTimeout = 5 * time.Second
const defaultMaxRetries = 3

// newHTTPClient builds the client from the internal configuration.
func newHTTPClient(cfg *config.Config, logger *logging.Logger) (*http.Client, error) {
	timeout := time.Duration(cfg.Provider.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}

	tlsConfig, err := buildClientTLS(cfg.Provider, logger)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// maxRetries is the configured number of retries, with the default applied.
func maxRetries(cfg *config.Config) int {
	if cfg == nil || cfg.Provider == nil || cfg.Provider.MaxRetries <= 0 {
		return defaultMaxRetries
	}
	return cfg.Provider.MaxRetries
}

// doWithRetries executes the request built by build, retrying a transport
// failure and, for an idempotent method, a 5xx or 429 response.
//
// Retrying a POST that failed with a transport error is safe here: either the
// request never reached the server, or the authorization code was already
// consumed and the retry fails with an explicit error.
func doWithRetries(client *http.Client, attempts int, logger *logging.Logger, build func() (*http.Request, error)) (*http.Response, error) {
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < attempts-1 && logger != nil {
				logger.Log(logging.LevelDebug, "Request to %s failed (%s), retrying (%d/%d)", req.URL.Host, err.Error(), attempt+2, attempts)
			}
			continue
		}

		if attempt < attempts-1 && isIdempotent(req.Method) && isRetryableStatus(resp.StatusCode) {
			if logger != nil {
				logger.Log(logging.LevelDebug, "Request to %s returned %d, retrying (%d/%d)", req.URL.Host, resp.StatusCode, attempt+2, attempts)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

// postFormWithRetries posts a form, with retries.
func postFormWithRetries(client *http.Client, attempts int, logger *logging.Logger, endpoint string, values url.Values) (*http.Response, error) {
	return doWithRetries(client, attempts, logger, func() (*http.Request, error) {
		body := strings.NewReader(values.Encode())
		req, err := http.NewRequest(http.MethodPost, endpoint, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	})
}

func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// buildClientTLS assembles the TLS configuration of the transport.
func buildClientTLS(provider *config.ProviderConfig, logger *logging.Logger) (*tls.Config, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	caValue := provider.CABundle
	if caValue == "" {
		caValue = provider.CABundleFile
	}

	if caValue != "" {
		data, err := readValueOrFile(caValue)
		if err != nil {
			return nil, fmt.Errorf("reading clientConfig.tls.ca: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(data); !ok {
			logger.Log(logging.LevelWarn, "Failed to append the CA bundle. Using system certificates only.")
		}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: provider.InsecureSkipVerifyBool,
		RootCAs:            rootCAs,
	}

	if provider.ClientCert != "" || provider.ClientKey != "" {
		if provider.ClientCert == "" || provider.ClientKey == "" {
			return nil, errors.New("clientConfig.tls.cert and clientConfig.tls.key must be set together")
		}

		certPEM, err := readValueOrFile(provider.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("reading clientConfig.tls.cert: %w", err)
		}
		keyPEM, err := readValueOrFile(provider.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("reading clientConfig.tls.key: %w", err)
		}

		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing clientConfig.tls.cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// readValueOrFile accepts either the PEM content itself or a file path, like
// the TLS options of Traefik OSS. A `base64:` prefix marks the PEM content
// encoded in base64.
func readValueOrFile(value string) ([]byte, error) {
	if strings.HasPrefix(value, "base64:") {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "base64:"))
	}
	if strings.Contains(value, "-----BEGIN") {
		return []byte(value), nil
	}
	return os.ReadFile(value)
}
