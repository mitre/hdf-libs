// Package tenablesc fetches scan results from a live Tenable.SC instance
// and pipes them through the nessus-to-hdf converter. Tenable.SC's
// downloadType=v2 endpoint returns a .nessus XML payload (sometimes
// wrapped in a single-entry zip archive); both shapes are handled.
//
// Auth: caller supplies access/secret keys via env vars
// (TENABLE_SC_ACCESS_KEY, TENABLE_SC_SECRET_KEY) at the CLI layer.
// The library reads them inside each method, never on the Params struct.
package tenablesc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	nessusconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nessus-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const (
	// defaultFetchTimeout applies when the caller has not set a deadline.
	defaultFetchTimeout = 5 * time.Minute

	// defaultMaxResponseSize caps any single response at 50MB to prevent
	// memory exhaustion from malicious or misconfigured servers. The CLI
	// surface lets users override via TenableSCParams.MaxBytes (set from
	// --max-size).
	defaultMaxResponseSize int64 = 50 * 1024 * 1024

	envAccessKey = "TENABLE_SC_ACCESS_KEY"
	envSecretKey = "TENABLE_SC_SECRET_KEY" //#nosec G101 -- env var name, not a credential

	// listFields mirrors the heimdall2 query — the minimal set
	// callers need to render a scan picker.
	listFields = "name,description,details,scannedIPs,totalChecks,startTime,finishTime,status"
)

// scanIDPattern accepts positive integers with no leading zeros. Tenable.SC
// scan result IDs are positive int64 values; rejecting everything else
// prevents path-traversal and SSRF when the ID is interpolated into the
// URL.
var scanIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)

// TenableScanResult is the per-scan record returned by ListScans. Fields
// match the heimdall2 query selectors verbatim.
type TenableScanResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Details     string `json:"details,omitempty"`
	ScannedIPs  string `json:"scannedIPs"`
	TotalChecks string `json:"totalChecks,omitempty"`
	StartTime   string `json:"startTime"`
	FinishTime  string `json:"finishTime"`
	Status      string `json:"status"`
}

// TenableSCParams holds parameters for a live Tenable.SC fetch.
// Construction validates only URL; ScanID is validated per-method
// (FetchScanToHDF needs it; VerifyCredentials and ListScans don't).
type TenableSCParams struct {
	// URL is the Tenable.SC server base URL (http or https only).
	URL string

	// ScanID is the Tenable.SC scan result ID — required for
	// FetchScanToHDF, ignored by other methods.
	ScanID string

	// MaxBytes caps any single response body. Zero means use
	// defaultMaxResponseSize.
	MaxBytes int64
}

// TenableSCFetcher fetches Tenable.SC scan data and feeds it through
// nessus-to-hdf.
type TenableSCFetcher struct {
	client *http.Client
	params TenableSCParams
}

// NewTenableSCFetcher creates a fetcher after validating the URL.
// Credentials are read from env vars at method-call time.
func NewTenableSCFetcher(params TenableSCParams, tlsOpts shared.TLSOptions) (*TenableSCFetcher, error) {
	if err := validateTenableSCURL(params.URL); err != nil {
		return nil, err
	}
	client, err := shared.NewHTTPClient(tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	return &TenableSCFetcher{client: client, params: params}, nil
}

// NewTenableSCFetcherWithClient creates a fetcher with an injected HTTP
// client. Use when the caller wants to control TLS/auth/transport in the
// application layer instead of relying on default discovery.
func NewTenableSCFetcherWithClient(params TenableSCParams, client *http.Client) (*TenableSCFetcher, error) {
	if err := validateTenableSCURL(params.URL); err != nil {
		return nil, err
	}
	return &TenableSCFetcher{client: client, params: params}, nil
}

func validateTenableSCURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("tenable.sc URL is required")
	}
	if _, err := shared.ValidateAndBuildAPIURL(rawURL, "/", "tenable.sc"); err != nil {
		return err
	}
	return nil
}

// validateScanID rejects anything that isn't a positive integer of
// reasonable length. Used as a defense against SSRF / path traversal
// when the ID gets interpolated into the URL.
func validateScanID(id string) error {
	if id == "" {
		return fmt.Errorf("tenable.sc scan ID is required")
	}
	if !scanIDPattern.MatchString(id) {
		return fmt.Errorf("tenable.sc scan ID %q is invalid: must be a positive integer", id)
	}
	return nil
}

// loadCredentials reads access + secret keys from env. Returns a clear
// error naming the missing variable when one is absent. Never includes
// the key VALUES in error messages.
func loadCredentials() (ak, sk string, err error) {
	ak = os.Getenv(envAccessKey)
	if ak == "" {
		return "", "", fmt.Errorf("%s environment variable is not set", envAccessKey)
	}
	sk = os.Getenv(envSecretKey)
	if sk == "" {
		return "", "", fmt.Errorf("%s environment variable is not set", envSecretKey)
	}
	return ak, sk, nil
}

// authHeader returns the Tenable.SC API-key header value.
func authHeader(ak, sk string) string {
	return fmt.Sprintf("accesskey=%s; secretkey=%s", ak, sk)
}

// maxBytes returns the configured cap, defaulting when zero.
func (f *TenableSCFetcher) maxBytes() int64 {
	if f.params.MaxBytes > 0 {
		return f.params.MaxBytes
	}
	return defaultMaxResponseSize
}

// applyDefaultDeadline returns a ctx + cancel func. If the caller's ctx
// already has a deadline, returns it unmodified with a no-op cancel.
// The caller is responsible for invoking the cancel function via defer.
func applyDefaultDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	//nolint:gosec // G118 false positive — cancel func is returned to caller for defer
	return context.WithTimeout(ctx, defaultFetchTimeout)
}

// buildRequest constructs an HTTP request with the x-apikey header and
// path-validated URL. path must begin with a leading slash.
func (f *TenableSCFetcher) buildRequest(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Request, error) {
	u, err := shared.ValidateAndBuildAPIURL(f.params.URL, path, "tenable.sc")
	if err != nil {
		return nil, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	ak, sk, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("x-apikey", authHeader(ak, sk))
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// VerifyCredentials issues a single GET /rest/currentUser. 200 means the
// configured access/secret keys authenticate; 401/403 mean they don't;
// any other status is treated as ambiguous.
func (f *TenableSCFetcher) VerifyCredentials(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := applyDefaultDeadline(ctx)
	defer cancel()

	req, err := f.buildRequest(ctx, http.MethodGet, "/rest/currentUser", nil, nil)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("tenable.sc request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("tenable.sc credentials unauthorized (HTTP %d)", resp.StatusCode)
	default:
		return fmt.Errorf("tenable.sc verify returned unexpected HTTP %d", resp.StatusCode)
	}
}

// ListScans queries /rest/scanResult for usable scans in the given time
// window. startTime / endTime are unix seconds; 0 for endTime defaults
// to "now".
func (f *TenableSCFetcher) ListScans(ctx context.Context, startTime, endTime int64) ([]TenableScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := applyDefaultDeadline(ctx)
	defer cancel()

	if endTime == 0 {
		endTime = time.Now().Unix()
	}

	q := url.Values{}
	q.Set("fields", listFields)
	q.Set("startTime", strconv.FormatInt(startTime, 10))
	q.Set("endTime", strconv.FormatInt(endTime, 10))

	req, err := f.buildRequest(ctx, http.MethodGet, "/rest/scanResult", q, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tenable.sc list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkHTTPStatus(resp, "list scans"); err != nil {
		return nil, err
	}

	body, err := shared.ReadLimitedBody(resp.Body, f.maxBytes())
	if err != nil {
		return nil, fmt.Errorf("tenable.sc list response: %w", err)
	}

	var envelope struct {
		Response struct {
			Usable []TenableScanResult `json:"usable"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("tenable.sc list response: invalid JSON: %w", err)
	}
	return envelope.Response.Usable, nil
}

// FetchScanToHDF downloads scan result params.ScanID and feeds the
// extracted .nessus XML through nessus-to-hdf. Tenable's
// downloadType=v2 returns either a raw .nessus payload or a zip
// containing a single .nessus entry; both are handled via magic-byte
// sniffing.
func (f *TenableSCFetcher) FetchScanToHDF(ctx context.Context, converterVersion string) (*hdf.HDFResults, error) {
	xml, err := f.FetchRawScan(ctx)
	if err != nil {
		return nil, err
	}
	return nessusconv.ConvertNessusToHDF(xml, converterVersion)
}

// FetchRawScan downloads scan result params.ScanID and returns the
// extracted .nessus XML bytes without running the converter. Use this
// when the caller wants the raw payload (e.g. `hdf fetch tenable-sc
// --format raw`) or wants to inspect/store the .nessus file directly.
func (f *TenableSCFetcher) FetchRawScan(ctx context.Context) ([]byte, error) {
	if err := validateScanID(f.params.ScanID); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := applyDefaultDeadline(ctx)
	defer cancel()

	return f.downloadScan(ctx)
}

// downloadScan does the POST + unzip-if-needed dance. Returns the raw
// .nessus XML bytes.
func (f *TenableSCFetcher) downloadScan(ctx context.Context) ([]byte, error) {
	path := "/rest/scanResult/" + f.params.ScanID + "/download"
	q := url.Values{}
	q.Set("downloadType", "v2")

	req, err := f.buildRequest(ctx, http.MethodPost, path, q, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tenable.sc download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkDownloadStatus(resp, f.params.ScanID); err != nil {
		return nil, err
	}

	body, err := shared.ReadLimitedBody(resp.Body, f.maxBytes())
	if err != nil {
		return nil, fmt.Errorf("tenable.sc download: %w", err)
	}

	return extractNessusXML(body, f.maxBytes())
}

// checkHTTPStatus returns an error for non-2xx responses with the
// operation name and status code, never including the key values.
func checkHTTPStatus(resp *http.Response, op string) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("tenable.sc %s unauthorized (HTTP %d)", op, resp.StatusCode)
	default:
		return fmt.Errorf("tenable.sc %s returned HTTP %d", op, resp.StatusCode)
	}
}

// checkDownloadStatus is checkHTTPStatus specialized for the download
// path — it includes the scan ID in the error so users can tell which
// scan failed.
func checkDownloadStatus(resp *http.Response, scanID string) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("tenable.sc download unauthorized (HTTP 401)")
	case http.StatusForbidden:
		// 403 from Tenable.SC on a download means either bad
		// permissions OR an incomplete/corrupt scan. Surface both.
		return fmt.Errorf("tenable.sc download forbidden (HTTP 403) — scan may be incomplete or credentials lack download permission")
	case http.StatusNotFound:
		return fmt.Errorf("tenable.sc scan %s not found (HTTP 404)", scanID)
	default:
		return fmt.Errorf("tenable.sc scan %s download returned HTTP %d", scanID, resp.StatusCode)
	}
}

// zipLocalFileMagic is the local-file-header signature for a PKZIP
// archive. zipEOCDMagic is the End-of-Central-Directory record — an
// empty zip with no file entries starts with this instead.
var (
	zipLocalFileMagic = []byte{0x50, 0x4b, 0x03, 0x04}
	zipEOCDMagic      = []byte{0x50, 0x4b, 0x05, 0x06}
)

// looksLikeZip returns true if body begins with either zip signature.
func looksLikeZip(body []byte) bool {
	return bytes.HasPrefix(body, zipLocalFileMagic) || bytes.HasPrefix(body, zipEOCDMagic)
}

// extractNessusXML returns the .nessus XML payload. body may be either
// raw XML or a zip archive whose first entry holds the XML. Caps the
// extracted XML at maxBytes so a small zip with a bombed expansion
// can't OOM us.
func extractNessusXML(body []byte, maxBytes int64) ([]byte, error) {
	if !looksLikeZip(body) {
		return body, nil
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("tenable.sc download: invalid zip: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("tenable.sc download: zip is empty")
	}

	// Heimdall2 takes the first entry regardless of name; we do the same
	// and let the nessus converter complain if the bytes aren't XML.
	first := zr.File[0]
	rc, err := first.Open()
	if err != nil {
		return nil, fmt.Errorf("tenable.sc download: failed to open zip entry %q: %w", first.Name, err)
	}
	defer func() { _ = rc.Close() }()

	xml, err := shared.ReadLimitedBody(rc, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("tenable.sc download: zip entry %q: %w", first.Name, err)
	}
	return xml, nil
}
