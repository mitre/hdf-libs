// Package fetchers implements live API fetch for security tools that have no
// static export format. Each fetcher retrieves data from a remote API and
// marshals it into the same JSON format that the corresponding file-based
// converter already reads.
package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"

	awsconfigconv "github.com/mitre/hdf-converters/converters/aws-config-to-hdf/go"
)

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
}

// AWSConfigParams holds parameters for a live AWS Config fetch.
type AWSConfigParams struct {
	// Region is required.
	Region string
	// AccessKeyID and SecretAccessKey are optional; when absent the standard
	// AWS credential chain is used (env vars, ~/.aws/credentials, IAM role).
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string //nolint:gosec // not a hardcoded credential; user-supplied flag value
}

// AWSConfigFetcher fetches AWS Config compliance data from the AWS API and
// returns it as ConfigRulesFile JSON, ready for ConvertAWSConfigToHDF.
type AWSConfigFetcher struct {
	client ConfigServiceClient
}

// NewAWSConfigFetcher creates a fetcher using live AWS credentials.
func NewAWSConfigFetcher(ctx context.Context, params AWSConfigParams) (*AWSConfigFetcher, error) {
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(params.Region))

	if params.AccessKeyID != "" && params.SecretAccessKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				params.AccessKeyID,
				params.SecretAccessKey,
				params.SessionToken,
			),
		))
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
	rules, err := f.fetchAllConfigRules(ctx)
	if err != nil {
		return nil, err
	}

	for i := range rules {
		results, err := f.fetchEvaluationResults(ctx, rules[i].ConfigRuleName)
		if err != nil {
			return nil, fmt.Errorf("fetching results for rule %s: %w", rules[i].ConfigRuleName, err)
		}
		rules[i].EvaluationResults = results
	}

	file := awsconfigconv.ConfigRulesFile{ConfigRules: rules}
	return json.Marshal(file)
}

// fetchAllConfigRules pages through DescribeConfigRules and returns all rules.
func (f *AWSConfigFetcher) fetchAllConfigRules(ctx context.Context) ([]awsconfigconv.ConfigRule, error) {
	var rules []awsconfigconv.ConfigRule
	var nextToken *string

	for {
		out, err := f.client.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeConfigRules: %w", err)
		}

		for _, r := range out.ConfigRules {
			rules = append(rules, convertSDKConfigRule(r))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return rules, nil
}

// fetchEvaluationResults pages through GetComplianceDetailsByConfigRule for one rule.
func (f *AWSConfigFetcher) fetchEvaluationResults(
	ctx context.Context,
	ruleName string,
) ([]awsconfigconv.EvaluationResult, error) {
	var results []awsconfigconv.EvaluationResult
	var nextToken *string

	for {
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
