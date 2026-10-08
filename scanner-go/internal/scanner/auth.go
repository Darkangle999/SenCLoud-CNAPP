package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const assumeRoleSessionName = "odineyes-go-inventory-scan"

var roleARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/[\w+=,.@/-]+$`)

func loadAccountConfig(ctx context.Context, accountID, roleARN, externalID, region string) (aws.Config, error) {
	base, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithRetryMaxAttempts(6),
		config.WithRetryMode(aws.RetryModeAdaptive),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS configuration: %w", err)
	}

	baseSTS := sts.NewFromConfig(base)
	caller, err := baseSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return aws.Config{}, fmt.Errorf("resolve scanner AWS identity: %w", err)
	}
	callerAccount := aws.ToString(caller.Account)
	callerARN := aws.ToString(caller.Arn)
	if callerAccount == accountID {
		return base, nil
	}
	if roleARN == "" {
		return aws.Config{}, fmt.Errorf(
			"cannot scan account %s: no role_arn registered and scanner credentials belong to account %s",
			accountID, valueOrUnknown(callerAccount),
		)
	}
	match := roleARNPattern.FindStringSubmatch(roleARN)
	if match == nil {
		return aws.Config{}, fmt.Errorf("role_arn is not a valid AWS IAM role ARN")
	}
	if match[1] != accountID {
		return aws.Config{}, fmt.Errorf(
			"role_arn belongs to account %s, not requested account %s", match[1], accountID,
		)
	}
	if strings.HasSuffix(callerARN, ":root") {
		return aws.Config{}, fmt.Errorf(
			"cannot scan account %s: scanner is using AWS root credentials; root cannot call sts:AssumeRole",
			accountID,
		)
	}

	provider := stscreds.NewAssumeRoleProvider(baseSTS, roleARN, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = assumeRoleSessionName
		options.Duration = time.Hour
		if externalID != "" {
			options.ExternalID = aws.String(externalID)
		}
	})
	assumed := base
	assumed.Credentials = aws.NewCredentialsCache(provider)

	identity, err := sts.NewFromConfig(assumed).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return aws.Config{}, fmt.Errorf("AssumeRole failed for account %s: %w", accountID, err)
	}
	if actual := aws.ToString(identity.Account); actual != accountID {
		return aws.Config{}, fmt.Errorf(
			"assumed role identity mismatch: requested account %s but AWS returned %s",
			accountID, valueOrUnknown(actual),
		)
	}
	return assumed, nil
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
