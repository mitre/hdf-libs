package fetchers

import (
	"fmt"
	"net/url"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

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
