package fetchers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// TLSOptions configures TLS behavior for all API-based fetchers.
// Zero value means standard TLS with system CA pool.
type TLSOptions struct {
	// CACertPath is the path to a PEM-encoded CA certificate bundle.
	// When set, these CAs are appended to the system pool.
	CACertPath string

	// Insecure disables TLS certificate verification entirely.
	// This is intended for development/testing only and prints a warning to stderr.
	Insecure bool
}

// NewHTTPClient creates an *http.Client configured with TLS settings from opts.
// If opts is zero-valued, a plain client with reasonable timeouts is returned.
func NewHTTPClient(opts TLSOptions) (*http.Client, error) {
	tlsConfig, err := buildTLSConfig(opts)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return &http.Client{Transport: transport}, nil
}

// buildTLSConfig constructs a *tls.Config from TLSOptions.
func buildTLSConfig(opts TLSOptions) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if opts.Insecure {
		tlsConfig.InsecureSkipVerify = true //#nosec G402 -- user explicitly requested --insecure
		fmt.Fprintln(os.Stderr, "WARNING: TLS certificate verification is disabled. This is insecure.")
		return tlsConfig, nil
	}

	if opts.CACertPath != "" {
		pool, err := loadCACertPool(opts.CACertPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// loadCACertPool reads a PEM-encoded CA bundle and returns a cert pool
// containing both the system CAs and the provided certificates.
func loadCACertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path) //#nosec G304 -- path is user-provided CA cert, intentional
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file %q: %w", path, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		// Fall back to an empty pool if the system pool is unavailable.
		pool = x509.NewCertPool()
	}

	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("CA certificate file %q contains no valid PEM certificates", path)
	}

	return pool, nil
}

// ValidateAndBuildAPIURL validates that rawURL uses http/https and returns a
// clean url.URL with the given path. This prevents SSRF via non-HTTP schemes
// and breaks the gosec G704 taint chain from user-provided URLs.
func ValidateAndBuildAPIURL(rawURL, path, toolName string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid %s URL: %w", toolName, err)
	}
	var scheme string
	switch parsed.Scheme {
	case schemeHTTPS:
		scheme = schemeHTTPS
	case schemeHTTP:
		scheme = schemeHTTP
	default:
		return nil, fmt.Errorf("invalid %s URL scheme %q: must use http or https", toolName, parsed.Scheme)
	}
	return &url.URL{
		Scheme: scheme,
		Host:   parsed.Host,
		Path:   path,
	}, nil
}

// readLimitedBody reads up to maxSize bytes from r. If the response body exceeds
// maxSize, it returns an error instead of silently truncating, which would cause
// confusing JSON parse errors downstream.
func readLimitedBody(r io.Reader, maxSize int64) ([]byte, error) {
	// Read one extra byte to detect truncation.
	body, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("response body exceeded %d byte limit", maxSize)
	}
	return body, nil
}
