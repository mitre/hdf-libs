// Package gitlab fetches CI job artifacts from a GitLab instance and returns
// them as raw bytes, ready for the appropriate format-specific HDF converter.
package gitlab

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"gopkg.in/yaml.v3"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const (
	// gitlabFetchTimeout is applied when the caller has not set a deadline.
	gitlabFetchTimeout = 5 * time.Minute

	// gitlabMaxResponseSize limits the response body to prevent memory exhaustion.
	gitlabMaxResponseSize = 10 * 1024 * 1024 // 10MB
)

// GitLabParams holds parameters for a live GitLab artifact fetch.
type GitLabParams struct {
	// URL is the GitLab instance base URL (default: https://gitlab.com).
	URL string
	// ProjectID is the project ID or URL-encoded namespace/project path (required).
	ProjectID string
	// Ref is the branch or tag name (default: main).
	Ref string
	// ScanType selects the default artifact filename (sast, dast, etc.).
	ScanType string
	// ArtifactPath overrides the default artifact filename.
	ArtifactPath string
	// JobName is the CI job name that produced the artifact (required).
	JobName string
	// MaxResponseSize overrides the default 10MB response size limit.
	// 0 means use the default (gitlabMaxResponseSize).
	// -1 means no limit.
	MaxResponseSize int64
}

// GitLabFetcher fetches a GitLab pipeline security report artifact.
type GitLabFetcher struct {
	client *http.Client
	params GitLabParams
}

// NewGitLabFetcher creates a fetcher after validating the server URL.
// The token is resolved at Fetch time from environment variables or glab CLI config.
func NewGitLabFetcher(params GitLabParams, tlsOpts shared.TLSOptions) (*GitLabFetcher, error) {
	if err := validateGitLabURL(params.URL); err != nil {
		return nil, err
	}
	client, err := shared.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	return &GitLabFetcher{
		client: client,
		params: params,
	}, nil
}

// NewGitLabFetcherWithClient creates a fetcher with an injected HTTP client.
// Use this constructor when the caller wants to handle TLS/auth/transport
// configuration in the application layer rather than relying on default
// discovery via TLSOptions.
func NewGitLabFetcherWithClient(params GitLabParams, client *http.Client) (*GitLabFetcher, error) {
	if err := validateGitLabURL(params.URL); err != nil {
		return nil, err
	}
	return &GitLabFetcher{
		client: client,
		params: params,
	}, nil
}

// validateGitLabURL ensures the URL parses and uses only http or https.
func validateGitLabURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("GitLab URL is required")
	}
	if _, err := buildGitLabBaseURL(rawURL); err != nil {
		return err
	}
	return nil
}

// buildGitLabBaseURL validates the base URL and returns a safe URL with scheme checked.
func buildGitLabBaseURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GitLab URL: %w", err)
	}
	// SSRF prevention: only allow http/https schemes
	var scheme string
	switch parsed.Scheme {
	case "https":
		scheme = "https"
	case "http":
		scheme = "http"
	default:
		return nil, fmt.Errorf("invalid GitLab URL scheme %q: must use http or https", parsed.Scheme)
	}
	return &url.URL{
		Scheme: scheme,
		Host:   parsed.Host,
	}, nil
}

// Fetch downloads the artifact from GitLab and returns the raw bytes.
func (f *GitLabFetcher) Fetch(ctx context.Context) ([]byte, error) {
	baseURL, err := buildGitLabBaseURL(f.params.URL)
	if err != nil {
		return nil, err
	}

	token, err := resolveGitLabToken(baseURL.Host)
	if err != nil {
		return nil, err
	}

	// Apply a default deadline when the caller has not set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, gitlabFetchTimeout)
		defer cancel()
	}

	artifactPath := f.params.ArtifactPath
	if artifactPath == "" {
		artifactPath = artifactPathForScanType(f.params.ScanType)
	}

	ref := f.params.Ref
	if ref == "" {
		ref = "main"
	}

	// Build the API URL:
	// GET /api/v4/projects/:id/jobs/artifacts/:ref/raw/*artifact_path?job=:job_name
	//
	// RawPath is set alongside Path to prevent double-encoding. PathEscape
	// turns "/" → "%2F" in namespace-style project IDs like "group/project",
	// but assigning that to url.URL.Path causes String() to re-encode the
	// "%" → "%25", producing "%252F". Setting RawPath tells String() to use
	// the pre-encoded form verbatim.
	rawAPIPath := fmt.Sprintf("/api/v4/projects/%s/jobs/artifacts/%s/raw/%s",
		url.PathEscape(f.params.ProjectID),
		url.PathEscape(ref),
		artifactPath,
	)

	apiURL := &url.URL{
		Scheme:   baseURL.Scheme,
		Host:     baseURL.Host,
		RawPath:  rawAPIPath,
		RawQuery: url.Values{"job": {f.params.JobName}}.Encode(),
	}
	// Path must be set (unescaped) so EscapedPath() validates RawPath.
	apiURL.Path, _ = url.PathUnescape(rawAPIPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// PRIVATE-TOKEN header is GitLab's standard auth mechanism for API tokens
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req) //#nosec G704 -- host is user-configured GitLab server; scheme validated in buildGitLabBaseURL
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab API returned HTTP %d", resp.StatusCode)
	}

	if f.params.MaxResponseSize < 0 {
		// No limit — read the entire body.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		return body, nil
	}

	maxSize := int64(gitlabMaxResponseSize)
	if f.params.MaxResponseSize > 0 {
		maxSize = f.params.MaxResponseSize
	}

	body, err := shared.ReadLimitedBody(resp.Body, maxSize)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
}

// resolveGitLabToken resolves a GitLab API token using this priority:
// 1. GITLAB_TOKEN env var
// 2. GLAB_TOKEN env var
// 3. glab CLI config file (~/.config/glab-cli/config.yml).
func resolveGitLabToken(hostname string) (string, error) {
	if token := os.Getenv("GITLAB_TOKEN"); token != "" {
		return token, nil
	}
	if token := os.Getenv("GLAB_TOKEN"); token != "" {
		return token, nil
	}

	token, err := readGlabConfigToken(hostname)
	if err == nil && token != "" {
		return token, nil
	}

	return "", fmt.Errorf(
		"no GitLab API token found\n" +
			"Set one of these environment variables:\n" +
			"  export GITLAB_TOKEN=<your-token>\n" +
			"  export GLAB_TOKEN=<your-token>\n" +
			"Or authenticate with the glab CLI:\n" +
			"  glab auth login",
	)
}

// glabConfig represents the glab CLI config file structure.
type glabConfig struct {
	Hosts map[string]glabHost `yaml:"hosts"`
}

type glabHost struct {
	Token string `yaml:"token"`
}

// readGlabConfigToken reads a token from the glab CLI config for the given hostname.
func readGlabConfigToken(hostname string) (string, error) {
	data, err := readGlabConfigFile()
	if err != nil {
		return "", err
	}

	var cfg glabConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parsing glab config: %w", err)
	}

	// Try exact hostname first (glab stores "localhost:9090" with port),
	// then fall back to bare hostname for standard ports.
	if hostCfg, ok := cfg.Hosts[hostname]; ok && hostCfg.Token != "" {
		return hostCfg.Token, nil
	}
	if h, _, err := splitHostPort(hostname); err == nil {
		if hostCfg, ok := cfg.Hosts[h]; ok && hostCfg.Token != "" {
			return hostCfg.Token, nil
		}
	}

	return "", fmt.Errorf("no token found for host %q in glab config", hostname)
}

// readGlabConfigFile finds and reads the glab CLI config file.
// Checks GLAB_CONFIG_DIR env var first, then the platform's XDG config
// directory (same resolution glab itself uses via adrg/xdg):
//   - Linux:   ~/.config/glab-cli/config.yml
//   - macOS:   ~/Library/Application Support/glab-cli/config.yml
//   - Windows: %LOCALAPPDATA%\glab-cli\config.yml
func readGlabConfigFile() ([]byte, error) {
	configDir := os.Getenv("GLAB_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join(xdg.ConfigHome, "glab-cli")
	}

	configPath := filepath.Join(configDir, "config.yml")
	data, err := os.ReadFile(configPath) //#nosec G304,G703 -- path from XDG config or GLAB_CONFIG_DIR env var
	if err != nil {
		return nil, fmt.Errorf("reading glab config at %s: %w", configPath, err)
	}
	return data, nil
}

// splitHostPort is a simple wrapper that handles hosts without ports.
func splitHostPort(hostport string) (string, string, error) {
	if !strings.Contains(hostport, ":") {
		return hostport, "", fmt.Errorf("no port")
	}
	// Use the last colon as separator (handles IPv6)
	idx := strings.LastIndex(hostport, ":")
	return hostport[:idx], hostport[idx+1:], nil
}

// artifactPathForScanType returns the default artifact filename for a scan type.
func artifactPathForScanType(scanType string) string {
	switch scanType {
	case "dast":
		return "gl-dast-report.json"
	case "dependency-scanning":
		return "gl-dependency-scanning-report.json"
	case "container-scanning":
		return "gl-container-scanning-report.json"
	case "secret-detection":
		return "gl-secret-detection-report.json"
	case "api-fuzzing":
		return "gl-api-fuzzing-report.json"
	default: // sast or empty
		return "gl-sast-report.json"
	}
}
