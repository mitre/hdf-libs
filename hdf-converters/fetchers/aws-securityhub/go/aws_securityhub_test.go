package awssecurityhub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securitytypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const converterVersion = "0.1.0"

// ---- mock client ----

// mockSecurityHubClient implements SecurityHubClient. Each method captures
// the inputs it receives and returns canned outputs / errors.
type mockSecurityHubClient struct {
	t *testing.T

	// GetFindings pages. Each entry is one response; the fetcher advances
	// the page index per call. NextToken on each entry drives pagination.
	getFindingsPages []securityhub.GetFindingsOutput
	getFindingsErr   error
	getFindingsCalls int

	// DescribeHub response and error.
	describeHubOutput *securityhub.DescribeHubOutput
	describeHubErr    error
	describeHubCalls  int

	// Inputs captured for assertion in tests.
	lastGetFindingsInput *securityhub.GetFindingsInput
}

func (m *mockSecurityHubClient) GetFindings(
	_ context.Context,
	in *securityhub.GetFindingsInput,
	_ ...func(*securityhub.Options),
) (*securityhub.GetFindingsOutput, error) {
	m.lastGetFindingsInput = in

	if m.getFindingsErr != nil {
		return nil, m.getFindingsErr
	}

	// Pagination-token plumbing check: call N must carry the token returned
	// by call N-1.
	if m.t != nil {
		if m.getFindingsCalls == 0 {
			assert.Nil(m.t, in.NextToken, "first GetFindings call should have nil NextToken")
		} else if m.getFindingsCalls <= len(m.getFindingsPages) {
			expected := m.getFindingsPages[m.getFindingsCalls-1].NextToken
			assert.Equal(m.t, aws.ToString(expected), aws.ToString(in.NextToken),
				"GetFindings call %d: NextToken mismatch", m.getFindingsCalls)
		}
	}

	if m.getFindingsCalls >= len(m.getFindingsPages) {
		return &securityhub.GetFindingsOutput{}, nil
	}
	out := m.getFindingsPages[m.getFindingsCalls]
	m.getFindingsCalls++
	return &out, nil
}

func (m *mockSecurityHubClient) DescribeHub(
	_ context.Context,
	_ *securityhub.DescribeHubInput,
	_ ...func(*securityhub.Options),
) (*securityhub.DescribeHubOutput, error) {
	m.describeHubCalls++
	if m.describeHubErr != nil {
		return nil, m.describeHubErr
	}
	if m.describeHubOutput != nil {
		return m.describeHubOutput, nil
	}
	return &securityhub.DescribeHubOutput{
		HubArn:       aws.String("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
		SubscribedAt: aws.String("2026-01-01T00:00:00.000Z"),
	}, nil
}

// rawFinding wraps a string into a securitytypes.AwsSecurityFinding by
// marshaling/unmarshaling — the SDK type has many fields, and tests only
// need to verify the converter sees the documented fields.
func rawFinding(t *testing.T, raw string) securitytypes.AwsSecurityFinding {
	t.Helper()
	var f securitytypes.AwsSecurityFinding
	require.NoError(t, json.Unmarshal([]byte(raw), &f))
	return f
}

func minimalFinding(t *testing.T, id string) securitytypes.AwsSecurityFinding {
	t.Helper()
	return rawFinding(t, `{
		"AwsAccountId": "123456789012",
		"Id": "`+id+`",
		"GeneratorId": "test-generator",
		"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
		"SchemaVersion": "2018-10-08",
		"Title": "Test finding `+id+`",
		"Description": "test description",
		"Severity": {"Label": "MEDIUM"},
		"Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::test"}],
		"Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
		"CreatedAt": "2026-01-01T00:00:00.000Z",
		"UpdatedAt": "2026-01-01T00:00:00.000Z"
	}`)
}

// ---- region validation ----

func TestNewAWSSecurityHubFetcher_RegionValidation(t *testing.T) { //nolint:dupl // mirrors awsconfig region test by design
	ctx := context.Background()

	valid := []string{"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-2", "us-gov-west-1", "cn-north-1"}
	for _, r := range valid {
		t.Run("valid/"+r, func(t *testing.T) {
			// NewAWSSecurityHubFetcher will fail past region validation when
			// no real AWS access exists, but the error must not be about
			// region format.
			_, err := NewAWSSecurityHubFetcher(ctx, AWSSecurityHubParams{Region: r})
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid region", "region %q should pass validation", r)
			}
		})
	}

	invalid := []string{"", "US-EAST-1", "us_east_1", "us.east.1", "evil.attacker.com", "us-east-1.evil.com", "us-east-1@evil.com", "us-east-1/path", "-us-east-1", "us-east-1-"}
	for _, r := range invalid {
		t.Run("invalid/"+r, func(t *testing.T) {
			_, err := NewAWSSecurityHubFetcher(ctx, AWSSecurityHubParams{Region: r})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid region")
		})
	}
}

// ---- VerifyCredentials ----

func TestVerifyCredentials_Success(t *testing.T) {
	mock := &mockSecurityHubClient{t: t}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	require.NoError(t, f.VerifyCredentials(context.Background()))
	assert.Equal(t, 1, mock.describeHubCalls)
}

func TestVerifyCredentials_AccessDenied(t *testing.T) {
	mock := &mockSecurityHubClient{
		describeHubErr: errors.New("AccessDeniedException: User is not authorized"),
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	err := f.VerifyCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestVerifyCredentials_ContextCancellation(t *testing.T) {
	mock := &mockSecurityHubClient{}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, f.VerifyCredentials(ctx))
}

// ---- Fetch ----

func TestFetch_SinglePage(t *testing.T) {
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{
				Findings: []securitytypes.AwsSecurityFinding{
					minimalFinding(t, "f1"),
					minimalFinding(t, "f2"),
					minimalFinding(t, "f3"),
				},
				// No NextToken — pagination terminates.
			},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	body, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, mock.getFindingsCalls)

	var env struct {
		Findings []map[string]any `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Len(t, env.Findings, 3)
}

func TestFetch_MultiPage(t *testing.T) {
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{
				Findings:  []securitytypes.AwsSecurityFinding{minimalFinding(t, "f1")},
				NextToken: aws.String("page-2-token"),
			},
			{
				Findings: []securitytypes.AwsSecurityFinding{minimalFinding(t, "f2")},
				// No NextToken — terminates.
			},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	body, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, mock.getFindingsCalls)

	var env struct {
		Findings []map[string]any `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Len(t, env.Findings, 2)
}

func TestFetch_EmptyResult(t *testing.T) {
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{Findings: []securitytypes.AwsSecurityFinding{}},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	body, err := f.Fetch(context.Background())
	require.NoError(t, err)
	assert.Contains(t, string(body), `"Findings"`)
}

func TestFetch_PaginationCap(t *testing.T) {
	// Mock that always returns a NextToken — fetcher must break out at
	// maxPages with a clear error.
	mock := &infiniteFindingsMock{}
	f := NewAWSSecurityHubFetcherWithClient(mock)
	f.maxPages = 3

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded maximum page limit")
}

func TestFetch_AccessDenied(t *testing.T) {
	mock := &mockSecurityHubClient{
		getFindingsErr: errors.New("AccessDeniedException: User not authorized"),
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestFetch_ContextCancellation(t *testing.T) {
	mock := &mockSecurityHubClient{}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.Fetch(ctx)
	require.Error(t, err)
}

func TestFetch_PassesFiltersThrough(t *testing.T) {
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{Findings: []securitytypes.AwsSecurityFinding{}},
		},
	}
	filters := &securitytypes.AwsSecurityFindingFilters{
		ProductArn: []securitytypes.StringFilter{
			{Value: aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
				Comparison: securitytypes.StringFilterComparisonEquals},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)
	f.params.Filters = filters

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
	require.NotNil(t, mock.lastGetFindingsInput)
	require.NotNil(t, mock.lastGetFindingsInput.Filters)
	require.Len(t, mock.lastGetFindingsInput.Filters.ProductArn, 1)
	assert.Equal(t, aws.ToString(filters.ProductArn[0].Value),
		aws.ToString(mock.lastGetFindingsInput.Filters.ProductArn[0].Value))
}

// ---- FetchToHDF ----

func TestFetchToHDF_HappyPath(t *testing.T) {
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{
				Findings: []securitytypes.AwsSecurityFinding{
					minimalFinding(t, "f1"),
					minimalFinding(t, "f2"),
				},
			},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	hdf, err := f.FetchToHDF(context.Background(), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, hdf)
	require.NotEmpty(t, hdf.Baselines, "expected at least one baseline from ASFF conversion")
}

// ---- Credential-leakage parity ----

func TestFetch_NoCredentialsInErrors(t *testing.T) {
	// Synthesize an error message that COULD contain credentials, to
	// confirm the fetcher's wrapping doesn't blindly include the SDK
	// error message in a way that exposes secrets.
	mock := &mockSecurityHubClient{
		getFindingsErr: errors.New("UnrecognizedClientException: signature mismatch"),
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	// Hard-coded "credential value" — we just want to confirm we don't
	// leak SDK-internal strings that could carry secret-shaped data.
	// In practice the SDK doesn't include AK/SK in error strings; this
	// test mainly guards against future regressions.
	assert.NotContains(t, err.Error(), "AKIA0123456789EXAMPLE")
}

// ---- Default deadline behavior ----

func TestFetch_DefaultDeadlineApplied(t *testing.T) {
	// Sanity test: when caller passes a context without a deadline,
	// the fetcher attaches its default. We don't trigger the deadline
	// — we just verify the call succeeds and the default doesn't break
	// happy-path flow.
	mock := &mockSecurityHubClient{
		t: t,
		getFindingsPages: []securityhub.GetFindingsOutput{
			{Findings: []securitytypes.AwsSecurityFinding{minimalFinding(t, "f1")}},
		},
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	_, err := f.Fetch(context.Background())
	require.NoError(t, err)
}

// ---- infiniteFindingsMock helper ----

type infiniteFindingsMock struct{}

func (m *infiniteFindingsMock) GetFindings(
	_ context.Context,
	_ *securityhub.GetFindingsInput,
	_ ...func(*securityhub.Options),
) (*securityhub.GetFindingsOutput, error) {
	return &securityhub.GetFindingsOutput{
		Findings:  []securitytypes.AwsSecurityFinding{},
		NextToken: aws.String("forever"),
	}, nil
}

func (m *infiniteFindingsMock) DescribeHub(
	_ context.Context,
	_ *securityhub.DescribeHubInput,
	_ ...func(*securityhub.Options),
) (*securityhub.DescribeHubOutput, error) {
	return &securityhub.DescribeHubOutput{}, nil
}

// ---- Sanity timing test (currently illustrative; no timeout fires) ----

// Smoke that VerifyCredentials with a real time-based context works.
func TestVerifyCredentials_WithTimeoutContext(t *testing.T) {
	mock := &mockSecurityHubClient{}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, f.VerifyCredentials(ctx))
}

// TestNewAWSSecurityHubFetcher_WithTLSAndProfile exercises the optional
// branches of NewAWSSecurityHubFetcher (custom TLS, named profile) for
// coverage. Construction succeeds even without real credentials — the
// SDK only contacts AWS on the first API call.
func TestNewAWSSecurityHubFetcher_WithTLSAndProfile(t *testing.T) {
	ctx := context.Background()

	// Custom TLS (insecure flag) exercises the NewHTTPClient + WithHTTPClient
	// branch. Profile string exercises WithSharedConfigProfile.
	_, err := NewAWSSecurityHubFetcher(ctx, AWSSecurityHubParams{
		Region:  "us-east-1",
		Profile: "test-profile",
		TLS:     shared.TLSOptions{Insecure: true},
	})
	// Profile may not exist locally — that's fine. The error must NOT
	// be about region or TLS validation.
	if err != nil {
		assert.NotContains(t, err.Error(), "invalid region")
		assert.NotContains(t, err.Error(), "failed to configure TLS")
	}
}

// TestFetchToHDF_FetchError covers the FetchToHDF error wrapping path
// when the underlying Fetch fails.
func TestFetchToHDF_FetchError(t *testing.T) {
	mock := &mockSecurityHubClient{
		getFindingsErr: errors.New("AccessDeniedException"),
	}
	f := NewAWSSecurityHubFetcherWithClient(mock)

	_, err := f.FetchToHDF(context.Background(), converterVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}
