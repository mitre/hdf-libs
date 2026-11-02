// Package awsconfig fetches compliance evaluations from AWS Config and pipes
// them through the aws-config-to-hdf converter.
package awsconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"

	awsconfigconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/fetchers/shared/go"
)

const (
	// defaultMaxPages caps pagination in both DescribeConfigRules and
	// GetComplianceDetailsByConfigRule to prevent unbounded memory growth or
	// infinite loops if the API returns malformed continuation tokens. AWS caps a
	// Region at 1000 rules, conformance-pack rules included, and a page holds up
	// to 100, so this ceiling is never reached in practice.
	defaultMaxPages = 1000

	// defaultFetchTimeout is applied when the caller has not set a deadline on
	// the context. A Region may hold up to 1000 rules, each read in turn.
	defaultFetchTimeout = 5 * time.Minute
)

// validRegionRe accepts any string that is a valid DNS hostname label:
// alphanumerics and hyphens, not starting or ending with a hyphen.
// This mirrors the defense-in-depth fix AWS applied across their SDKs
// (GHSA-3jcv-796g-cpjg / CVE-2026-22611) to prevent region strings from
// being interpolated into endpoint URLs in a way that could redirect traffic.
// Intentionally permissive about region structure (accepts us-gov-west-1,
// ap-southeast-2, cn-north-1, future regions) while blocking URL-special
// characters (dots, slashes, colons, @, ?, #).
var validRegionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)

// ConfigServiceClient is the subset of the AWS Config SDK used by the fetcher.
// Defined as an interface so tests can inject a mock without a live AWS account.
type ConfigServiceClient interface {
	DescribeConfigRules(
		ctx context.Context,
		params *configservice.DescribeConfigRulesInput,
		optFns ...func(*configservice.Options),
	) (*configservice.DescribeConfigRulesOutput, error)

	GetComplianceDetailsByConfigRule(
		ctx context.Context,
		params *configservice.GetComplianceDetailsByConfigRuleInput,
		optFns ...func(*configservice.Options),
	) (*configservice.GetComplianceDetailsByConfigRuleOutput, error)

	DescribeRemediationConfigurations(
		ctx context.Context,
		params *configservice.DescribeRemediationConfigurationsInput,
		optFns ...func(*configservice.Options),
	) (*configservice.DescribeRemediationConfigurationsOutput, error)
}

// AWSConfigParams holds parameters for a live AWS Config fetch.
type AWSConfigParams struct {
	// Region is required.
	Region string
	// Profile selects a named profile from ~/.aws/credentials or ~/.aws/config.
	// When empty, the standard AWS credential chain is used (env vars →
	// default profile → IAM instance role).
	Profile string
	// TLS configures custom CA certificates or insecure mode.
	TLS shared.TLSOptions
}

// AWSConfigFetcher fetches AWS Config compliance data from the AWS API and
// returns it as ConfigRulesFile JSON, ready for ConvertAWSConfigToHDF.
type AWSConfigFetcher struct {
	client   ConfigServiceClient
	maxPages int // 0 → defaultMaxPages
}

// NewAWSConfigFetcher creates a fetcher using live AWS credentials.
func NewAWSConfigFetcher(ctx context.Context, params AWSConfigParams) (*AWSConfigFetcher, error) {
	if !validRegionRe.MatchString(params.Region) {
		return nil, fmt.Errorf("invalid region %q: must contain only lowercase letters, digits, and hyphens (e.g. us-east-1)", params.Region)
	}

	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(params.Region))

	if params.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(params.Profile))
	}

	// Inject custom HTTP client for TLS configuration (--ca-cert, --insecure).
	if params.TLS.CACertPath != "" || params.TLS.Insecure {
		httpClient, tlsErr := shared.NewHTTPClient(params.TLS)
		if tlsErr != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", tlsErr)
		}
		opts = append(opts, config.WithHTTPClient(httpClient))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSConfigFetcher{
		client: configservice.NewFromConfig(cfg),
	}, nil
}

// NewAWSConfigFetcherWithClient creates a fetcher with an injected client.
// Intended for testing only.
func NewAWSConfigFetcherWithClient(client ConfigServiceClient) *AWSConfigFetcher {
	return &AWSConfigFetcher{client: client}
}

// Fetch retrieves all AWS Config rules and their evaluation results, then
// marshals the combined data into ConfigRulesFile JSON.
func (f *AWSConfigFetcher) Fetch(ctx context.Context) ([]byte, error) {
	// Apply a default deadline when the caller has not set one, so a hung or
	// unreachable endpoint cannot block indefinitely.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultFetchTimeout)
		defer cancel()
	}

	rules, skipped, err := f.fetchAllConfigRules(ctx)
	if err != nil {
		return nil, err
	}
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: aws-config: skipped %d rule(s) whose evaluations the Config API "+
			"will not return (RuleEvaluationVisibility INTERNAL): %s\n", len(skipped), describeUnreadable(skipped))
	}

	for i := range rules {
		results, err := f.fetchEvaluationResults(ctx, rules[i].ConfigRuleName)
		if err != nil {
			return nil, fmt.Errorf("fetching results for rule %s: %w", rules[i].ConfigRuleName, err)
		}
		rules[i].EvaluationResults = results
	}

	// Remediation is optional enrichment: merge in each rule's remediation
	// configuration when present. Never fatal — a fetch must still succeed for
	// accounts with no remediations, or when the remediation API is unavailable.
	// Every fetched rule has readable evaluations, so all are remediation-eligible.
	ruleNames := make([]string, len(rules))
	for i := range rules {
		ruleNames[i] = rules[i].ConfigRuleName
	}
	remediations := f.fetchRemediations(ctx, ruleNames)
	for i := range rules {
		if rc, ok := remediations[rules[i].ConfigRuleName]; ok {
			rules[i].Remediation = rc
		}
	}

	file := awsconfigconv.ConfigRulesFile{ConfigRules: rules}
	return json.Marshal(file)
}

// unreadableRule is a rule whose evaluations the Config API will not return.
type unreadableRule struct {
	name  string
	owner string // CreatedBy: the service that provisioned the rule, when known
}

// evaluationsReadable is the API's own answer to whether GetComplianceDetails
// can return results: RuleEvaluationVisibility INTERNAL means it cannot. An
// unset value counts as readable so an older response never drops a rule; a
// read that then fails is handled per rule rather than guessed at here.
func evaluationsReadable(r types.ConfigRule) bool {
	return r.RuleEvaluationVisibility != types.RuleEvaluationVisibilityInternal
}

// describeUnreadable renders the skipped rules for the warning, naming the
// service that provisioned each one when the API reported it.
func describeUnreadable(skipped []unreadableRule) string {
	parts := make([]string, len(skipped))
	for i, u := range skipped {
		parts[i] = u.name
		if u.owner != "" {
			parts[i] += " (" + u.owner + ")"
		}
	}
	return strings.Join(parts, ", ")
}

// fetchAllConfigRules pages through DescribeConfigRules, returning the rules
// whose evaluations are readable and the ones skipped because they are not.
func (f *AWSConfigFetcher) fetchAllConfigRules(ctx context.Context) ([]awsconfigconv.ConfigRule, []unreadableRule, error) {
	limit := f.maxPages
	if limit <= 0 {
		limit = defaultMaxPages
	}

	var rules []awsconfigconv.ConfigRule
	var skipped []unreadableRule
	var nextToken *string

	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if page >= limit {
			return nil, nil, fmt.Errorf("DescribeConfigRules: exceeded maximum page limit (%d)", limit)
		}

		out, err := f.client.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("DescribeConfigRules: %w", err)
		}

		for _, r := range out.ConfigRules {
			if !evaluationsReadable(r) {
				skipped = append(skipped, unreadableRule{
					name:  aws.ToString(r.ConfigRuleName),
					owner: aws.ToString(r.CreatedBy),
				})
				continue
			}
			rules = append(rules, convertSDKConfigRule(r))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return rules, skipped, nil
}

// maxRemediationBatch is the DescribeRemediationConfigurations limit on rule
// names per request.
const maxRemediationBatch = 25

// fetchRemediations looks up remediation configurations for the given (already
// remediation-eligible) rule names, keyed by rule name. Remediation is optional
// enrichment: an API error never fails the fetch — the affected rules simply get
// no remediation (and thus no fix description), with a warning to stderr.
func (f *AWSConfigFetcher) fetchRemediations(ctx context.Context, ruleNames []string) map[string]*awsconfigconv.RemediationConfiguration {
	out := make(map[string]*awsconfigconv.RemediationConfiguration)
	for start := 0; start < len(ruleNames); start += maxRemediationBatch {
		if ctx.Err() != nil {
			break
		}
		end := start + maxRemediationBatch
		if end > len(ruleNames) {
			end = len(ruleNames)
		}
		batch := ruleNames[start:end]

		resp, err := f.client.DescribeRemediationConfigurations(ctx, &configservice.DescribeRemediationConfigurationsInput{
			ConfigRuleNames: batch,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: aws-config: skipping remediation for %d rule(s): %v\n", len(batch), err)
			continue
		}
		for _, rc := range resp.RemediationConfigurations {
			name := aws.ToString(rc.ConfigRuleName)
			if name == "" {
				continue
			}
			out[name] = &awsconfigconv.RemediationConfiguration{
				TargetType:    string(rc.TargetType),
				TargetID:      aws.ToString(rc.TargetId),
				TargetVersion: aws.ToString(rc.TargetVersion),
				Automatic:     rc.Automatic,
			}
		}
	}
	return out
}

// fetchEvaluationResults pages through GetComplianceDetailsByConfigRule for one rule.
func (f *AWSConfigFetcher) fetchEvaluationResults(
	ctx context.Context,
	ruleName string,
) ([]awsconfigconv.EvaluationResult, error) {
	limit := f.maxPages
	if limit <= 0 {
		limit = defaultMaxPages
	}

	var results []awsconfigconv.EvaluationResult
	var nextToken *string

	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page >= limit {
			return nil, fmt.Errorf("GetComplianceDetailsByConfigRule: exceeded maximum page limit (%d)", limit)
		}

		out, err := f.client.GetComplianceDetailsByConfigRule(ctx, &configservice.GetComplianceDetailsByConfigRuleInput{
			ConfigRuleName: aws.String(ruleName),
			Limit:          100,
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("GetComplianceDetailsByConfigRule: %w", err)
		}

		for _, er := range out.EvaluationResults {
			results = append(results, convertSDKEvaluationResult(er))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return results, nil
}

// convertSDKConfigRule maps an AWS SDK ConfigRule to our converter's type.
func convertSDKConfigRule(r types.ConfigRule) awsconfigconv.ConfigRule {
	rule := awsconfigconv.ConfigRule{
		ConfigRuleID:    aws.ToString(r.ConfigRuleId),
		ConfigRuleName:  aws.ToString(r.ConfigRuleName),
		ConfigRuleArn:   aws.ToString(r.ConfigRuleArn),
		Description:     aws.ToString(r.Description),
		InputParameters: aws.ToString(r.InputParameters),
	}
	if r.Source != nil {
		rule.Source = awsconfigconv.ConfigRuleSource{
			Owner:            string(r.Source.Owner),
			SourceIdentifier: aws.ToString(r.Source.SourceIdentifier),
		}
	}
	return rule
}

// convertSDKEvaluationResult maps an AWS SDK EvaluationResult to our converter's type.
func convertSDKEvaluationResult(er types.EvaluationResult) awsconfigconv.EvaluationResult {
	result := awsconfigconv.EvaluationResult{
		ComplianceType: string(er.ComplianceType),
		Annotation:     aws.ToString(er.Annotation),
	}

	if er.ConfigRuleInvokedTime != nil {
		result.ConfigRuleInvokedTime = er.ConfigRuleInvokedTime.UTC().Format(time.RFC3339Nano)
	}
	if er.ResultRecordedTime != nil {
		result.ResultRecordedTime = er.ResultRecordedTime.UTC().Format(time.RFC3339Nano)
	}

	if er.EvaluationResultIdentifier != nil && er.EvaluationResultIdentifier.EvaluationResultQualifier != nil {
		q := er.EvaluationResultIdentifier.EvaluationResultQualifier
		result.EvaluationResultIdentifier = awsconfigconv.EvaluationResultIdentifier{
			EvaluationResultQualifier: awsconfigconv.EvaluationResultQualifier{
				ConfigRuleName: aws.ToString(q.ConfigRuleName),
				ResourceType:   aws.ToString(q.ResourceType),
				ResourceID:     aws.ToString(q.ResourceId),
			},
		}
	}

	return result
}
