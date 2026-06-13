// Package awssecurityhub fetches ASFF findings from AWS Security Hub and
// pipes them through the asff-to-hdf converter.
//
// Auth is handled by the AWS SDK's standard credential chain — env vars,
// shared credentials file, IAM instance role, AssumeRole, etc. The library
// never touches credential material directly. Callers that want full
// transport control can construct their own SecurityHubClient and use
// NewAWSSecurityHubFetcherWithClient.
package awssecurityhub

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securitytypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	asffconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/asff-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const (
	// defaultMaxPages caps GetFindings pagination at 10_000 pages.
	// AWS Security Hub's per-call maximum is 100 findings; the cap allows
	// 1M findings per fetch, which is well past any realistic account
	// size after default standards.
	defaultMaxPages = 10_000

	// defaultFetchTimeout applies when the caller has not set a deadline.
	defaultFetchTimeout = 5 * time.Minute

	// defaultPageSize asks the SDK for the maximum page size (100). The
	// AWS SDK clamps higher values internally; this matches that ceiling.
	defaultPageSize = 100
)

// validRegionRe accepts strings that match a DNS hostname label —
// alphanumeric and hyphens, not starting or ending with a hyphen.
// Mirrors the awsconfig fetcher's defense (per GHSA-3jcv-796g-cpjg /
// CVE-2026-22611): unvalidated region strings interpolated into SDK
// endpoint URLs would create an SSRF vector.
var validRegionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)

// SecurityHubClient is the subset of the AWS SDK securityhub client surface
// used by the fetcher. Defined as an interface so tests can inject a mock.
type SecurityHubClient interface {
	GetFindings(ctx context.Context, in *securityhub.GetFindingsInput, opts ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
	DescribeHub(ctx context.Context, in *securityhub.DescribeHubInput, opts ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

// AWSSecurityHubParams holds parameters for a live Security Hub fetch.
type AWSSecurityHubParams struct {
	// Region is required.
	Region string
	// Profile selects a named profile from ~/.aws/credentials or ~/.aws/config.
	// When empty, the standard AWS credential chain is used.
	Profile string
	// TLS configures custom CA certificates or insecure mode.
	TLS shared.TLSOptions
	// Filters pass through to GetFindings. Optional; nil means unfiltered.
	Filters *securitytypes.AwsSecurityFindingFilters
}

// AWSSecurityHubFetcher fetches Security Hub findings.
type AWSSecurityHubFetcher struct {
	client   SecurityHubClient
	params   AWSSecurityHubParams
	maxPages int // 0 → defaultMaxPages
}

// NewAWSSecurityHubFetcher creates a fetcher using live AWS credentials.
func NewAWSSecurityHubFetcher(ctx context.Context, params AWSSecurityHubParams) (*AWSSecurityHubFetcher, error) {
	if !validRegionRe.MatchString(params.Region) {
		return nil, fmt.Errorf("invalid region %q: must contain only lowercase letters, digits, and hyphens (e.g. us-east-1)", params.Region)
	}

	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(params.Region))

	if params.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(params.Profile))
	}

	if params.TLS.CACertPath != "" || params.TLS.Insecure {
		httpClient, err := shared.NewHTTPClient(params.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		opts = append(opts, config.WithHTTPClient(httpClient))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSSecurityHubFetcher{
		client: securityhub.NewFromConfig(cfg),
		params: params,
	}, nil
}

// NewAWSSecurityHubFetcherWithClient creates a fetcher with an injected
// client. Used by tests and by callers that want full transport control.
func NewAWSSecurityHubFetcherWithClient(client SecurityHubClient) *AWSSecurityHubFetcher {
	return &AWSSecurityHubFetcher{client: client}
}

// VerifyCredentials issues a DescribeHub call. 2xx → nil; any error from
// the SDK is wrapped and surfaced.
func (f *AWSSecurityHubFetcher) VerifyCredentials(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := applyDefaultDeadline(ctx)
	defer cancel()

	if _, err := f.client.DescribeHub(ctx, &securityhub.DescribeHubInput{}); err != nil {
		return fmt.Errorf("aws-securityhub DescribeHub: %w", err)
	}
	return nil
}

// Fetch pages through GetFindings and returns the accumulated findings as
// the `{"Findings": [...]}` envelope that asff-to-hdf accepts.
func (f *AWSSecurityHubFetcher) Fetch(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := applyDefaultDeadline(ctx)
	defer cancel()

	limit := f.maxPages
	if limit <= 0 {
		limit = defaultMaxPages
	}

	var findings []securitytypes.AwsSecurityFinding
	var nextToken *string

	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= limit {
			return nil, fmt.Errorf("aws-securityhub GetFindings: exceeded maximum page limit (%d)", limit)
		}

		out, err := f.client.GetFindings(ctx, &securityhub.GetFindingsInput{
			NextToken:  nextToken,
			MaxResults: aws.Int32(defaultPageSize),
			Filters:    f.params.Filters,
		})
		if err != nil {
			return nil, fmt.Errorf("aws-securityhub GetFindings: %w", err)
		}

		findings = append(findings, out.Findings...)

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	envelope := struct {
		Findings []securitytypes.AwsSecurityFinding `json:"Findings"`
	}{Findings: findings}

	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("aws-securityhub: failed to marshal findings: %w", err)
	}
	return body, nil
}

// FetchToHDF runs Fetch and pipes the result through asff-to-hdf.
func (f *AWSSecurityHubFetcher) FetchToHDF(ctx context.Context, converterVersion string) (*hdf.HDFResults, error) {
	body, err := f.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	return asffconv.ConvertAsffToHDF(body, converterVersion)
}

// applyDefaultDeadline returns a ctx + cancel func. If the caller's ctx
// already has a deadline, returns it unmodified with a no-op cancel.
func applyDefaultDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	//nolint:gosec // G118 false positive — cancel func is returned to caller for defer
	return context.WithTimeout(ctx, defaultFetchTimeout)
}
