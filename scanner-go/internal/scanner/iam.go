package scanner

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

var administrativeManagedPolicies = map[string]struct{}{
	"AdministratorAccess": {},
	"IAMFullAccess":       {},
	"PowerUserAccess":     {},
}

type policyEvidence struct {
	hasAdmin    bool
	adminReason string
	complete    bool
	privesc     map[string]struct{}
	assumeRole  map[string]struct{}
	s3Read      map[string]struct{}
}

func newPolicyEvidence() policyEvidence {
	return policyEvidence{
		complete:   true,
		privesc:    make(map[string]struct{}),
		assumeRole: make(map[string]struct{}),
		s3Read:     make(map[string]struct{}),
	}
}

func (e *policyEvidence) mergeDocument(document map[string]any, reason string) {
	privesc, assumeRole, s3Read := analyzePolicyDocument(document)
	addStrings(e.privesc, privesc)
	addStrings(e.assumeRole, assumeRole)
	addStrings(e.s3Read, s3Read)
	if isAdminDocument(document) {
		e.hasAdmin = true
		if e.adminReason == "" {
			e.adminReason = reason
		}
	}
}

func (c *Collector) collectIAM(ctx context.Context) {
	client := iam.NewFromConfig(c.cfg, func(options *iam.Options) {
		options.Region = c.request.HomeRegion
	})
	c.collectIAMRoles(ctx, client)
	c.collectIAMUsers(ctx, client)
}

func (c *Collector) collectIAMRoles(ctx context.Context, client *iam.Client) {
	const sourceType = "aws.iam.role"
	count := 0
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, role := range page.Roles {
			if count >= c.maxItems {
				break
			}
			if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
				continue
			}
			raw, err := toMap(role)
			if err != nil {
				c.addError(sourceType, "iam.ListRoles.encode", nil, err)
				continue
			}
			trust := decodePolicyDocument(aws.ToString(role.AssumeRolePolicyDocument))
			raw["AssumeRolePolicyDocument"] = trust
			c.enrichIAMRole(ctx, client, raw, trust)
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "iam.ListRoles", nil, count, collectionErr)
}

func (c *Collector) enrichIAMRole(
	ctx context.Context,
	client *iam.Client,
	raw map[string]any,
	trust map[string]any,
) {
	name, _ := raw["RoleName"].(string)
	evidence := newPolicyEvidence()

	attached := iam.NewListAttachedRolePoliciesPaginator(
		client,
		&iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)},
	)
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			evidence.complete = false
			break
		}
		for _, policy := range page.AttachedPolicies {
			policyName := aws.ToString(policy.PolicyName)
			if _, ok := administrativeManagedPolicies[policyName]; ok {
				evidence.hasAdmin = true
				if evidence.adminReason == "" {
					evidence.adminReason = "managed policy " + policyName
				}
			}
			document, err := managedPolicyDocument(ctx, client, aws.ToString(policy.PolicyArn))
			if err != nil {
				evidence.complete = false
				continue
			}
			evidence.mergeDocument(document, "managed policy "+policyName+" (*:*)")
		}
	}

	inline := iam.NewListRolePoliciesPaginator(
		client,
		&iam.ListRolePoliciesInput{RoleName: aws.String(name)},
	)
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			evidence.complete = false
			break
		}
		for _, policyName := range page.PolicyNames {
			output, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(name),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				evidence.complete = false
				continue
			}
			evidence.mergeDocument(
				decodePolicyDocument(aws.ToString(output.PolicyDocument)),
				"inline policy "+policyName+" (*:*)",
			)
		}
	}

	raw["has_admin"] = evidence.hasAdmin
	raw["admin_reason"] = evidence.adminReason
	raw["privesc_actions"] = sortedKeys(evidence.privesc)
	raw["assume_role_resources"] = sortedKeys(evidence.assumeRole)
	raw["s3_read_resources"] = sortedKeys(evidence.s3Read)
	raw["policy_analysis_complete"] = evidence.complete

	roleARN, _ := raw["Arn"].(string)
	roleAccount := principalAccount(roleARN)
	assumableByEC2, external, principals := analyzeTrust(trust, roleAccount)
	raw["assumable_by_ec2"] = assumableByEC2
	raw["trust_external"] = external
	raw["trust_principals"] = principals

	raw["last_used_days"] = nil
	if output, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(name)}); err == nil &&
		output.Role != nil && output.Role.RoleLastUsed != nil {
		raw["last_used_days"] = daysSince(output.Role.RoleLastUsed.LastUsedDate)
	}
	raw["age_days"] = daysSince(timeFromMap(raw["CreateDate"]))
}

func (c *Collector) collectIAMUsers(ctx context.Context, client *iam.Client) {
	const sourceType = "aws.iam.user"
	count := 0
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, user := range page.Users {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(user)
			if err != nil {
				c.addError(sourceType, "iam.ListUsers.encode", nil, err)
				continue
			}
			c.enrichIAMUser(ctx, client, raw)
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "iam.ListUsers", nil, count, collectionErr)
}

func (c *Collector) enrichIAMUser(
	ctx context.Context,
	client *iam.Client,
	raw map[string]any,
) {
	name, _ := raw["UserName"].(string)
	evidence := newPolicyEvidence()

	attached := iam.NewListAttachedUserPoliciesPaginator(
		client,
		&iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)},
	)
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			evidence.complete = false
			break
		}
		for _, policy := range page.AttachedPolicies {
			policyName := aws.ToString(policy.PolicyName)
			if _, ok := administrativeManagedPolicies[policyName]; ok {
				evidence.hasAdmin = true
				if evidence.adminReason == "" {
					evidence.adminReason = "managed policy " + policyName
				}
			}
			document, err := managedPolicyDocument(ctx, client, aws.ToString(policy.PolicyArn))
			if err != nil {
				evidence.complete = false
				continue
			}
			evidence.mergeDocument(document, "managed policy "+policyName+" (*:*)")
		}
	}

	inline := iam.NewListUserPoliciesPaginator(
		client,
		&iam.ListUserPoliciesInput{UserName: aws.String(name)},
	)
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			evidence.complete = false
			break
		}
		for _, policyName := range page.PolicyNames {
			output, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName:   aws.String(name),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				evidence.complete = false
				continue
			}
			evidence.mergeDocument(
				decodePolicyDocument(aws.ToString(output.PolicyDocument)),
				"inline policy "+policyName+" (*:*)",
			)
		}
	}

	raw["has_admin"] = evidence.hasAdmin
	raw["admin_reason"] = evidence.adminReason
	raw["privesc_actions"] = sortedKeys(evidence.privesc)
	raw["assume_role_resources"] = sortedKeys(evidence.assumeRole)
	raw["s3_read_resources"] = sortedKeys(evidence.s3Read)
	raw["policy_analysis_complete"] = evidence.complete

	accessKeyActive := false
	maxKeyAge := 0
	var accessKeyLastUsed *int
	keys := iam.NewListAccessKeysPaginator(
		client,
		&iam.ListAccessKeysInput{UserName: aws.String(name)},
	)
	for keys.HasMorePages() {
		page, err := keys.NextPage(ctx)
		if err != nil {
			break
		}
		for _, key := range page.AccessKeyMetadata {
			if string(key.Status) != "Active" {
				continue
			}
			accessKeyActive = true
			if age := daysSince(key.CreateDate); age != nil && *age > maxKeyAge {
				maxKeyAge = *age
			}
			if key.AccessKeyId == nil {
				continue
			}
			output, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err != nil || output.AccessKeyLastUsed == nil {
				continue
			}
			accessKeyLastUsed = minAge(
				accessKeyLastUsed,
				daysSince(output.AccessKeyLastUsed.LastUsedDate),
			)
		}
	}

	consoleEnabled := false
	if _, err := client.GetLoginProfile(
		ctx,
		&iam.GetLoginProfileInput{UserName: aws.String(name)},
	); err == nil {
		consoleEnabled = true
	}

	mfaEnabled := false
	mfa := iam.NewListMFADevicesPaginator(
		client,
		&iam.ListMFADevicesInput{UserName: aws.String(name)},
	)
	for mfa.HasMorePages() {
		page, err := mfa.NextPage(ctx)
		if err != nil {
			break
		}
		if len(page.MFADevices) > 0 {
			mfaEnabled = true
			break
		}
	}

	raw["access_key_active"] = accessKeyActive
	raw["access_key_max_age_days"] = maxKeyAge
	raw["access_key_last_used_days"] = accessKeyLastUsed
	raw["console_enabled"] = consoleEnabled
	raw["mfa_enabled"] = mfaEnabled

	passwordLastUsed := daysSince(timeFromMap(raw["PasswordLastUsed"]))
	raw["last_used_days"] = minAge(accessKeyLastUsed, passwordLastUsed)
	raw["age_days"] = daysSince(timeFromMap(raw["CreateDate"]))
}

func managedPolicyDocument(
	ctx context.Context,
	client *iam.Client,
	policyARN string,
) (map[string]any, error) {
	policy, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return nil, err
	}
	versionID := ""
	if policy.Policy != nil {
		versionID = aws.ToString(policy.Policy.DefaultVersionId)
	}
	version, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, err
	}
	if version.PolicyVersion == nil {
		return map[string]any{}, nil
	}
	return decodePolicyDocument(aws.ToString(version.PolicyVersion.Document)), nil
}

func addStrings(target map[string]struct{}, values []string) {
	for _, value := range values {
		target[value] = struct{}{}
	}
}

func daysSince(value *time.Time) *int {
	if value == nil {
		return nil
	}
	instant := value.UTC()
	now := time.Now().UTC()
	if instant.After(now) {
		zero := 0
		return &zero
	}
	days := int(now.Sub(instant).Hours() / 24)
	return &days
}

func timeFromMap(value any) *time.Time {
	switch typed := value.(type) {
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err == nil {
			return &parsed
		}
	case time.Time:
		return &typed
	case *time.Time:
		return typed
	}
	return nil
}

func minAge(left, right *int) *int {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	if *right < *left {
		return right
	}
	return left
}
