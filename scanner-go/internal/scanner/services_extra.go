package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudwatchlogs "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func (c *Collector) collectLambda(ctx context.Context, region string) {
	const sourceType = "aws.lambda.function"
	client := lambda.NewFromConfig(c.cfg, func(options *lambda.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, function := range page.Functions {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(function)
			if err != nil {
				c.addError(sourceType, "lambda.ListFunctions.encode", regionRef, err)
				continue
			}
			raw["Region"] = region
			c.enrichLambda(ctx, client, raw)
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "lambda.ListFunctions", regionRef, count, collectionErr)
}

func (c *Collector) enrichLambda(
	ctx context.Context,
	client *lambda.Client,
	raw map[string]any,
) {
	name, _ := raw["FunctionName"].(string)
	raw["FunctionUrlAuthType"] = nil
	if output, err := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
		FunctionName: aws.String(name),
	}); err == nil {
		raw["FunctionUrlAuthType"] = string(output.AuthType)
	}
	raw["PublicPolicy"] = false
	if output, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: aws.String(name),
	}); err == nil {
		raw["PublicPolicy"] = hasWildcardPrincipal(aws.ToString(output.Policy))
	}
}

func (c *Collector) collectLoadBalancers(ctx context.Context, region string) {
	const sourceType = "aws.elbv2.load_balancer"
	client := elasticloadbalancingv2.NewFromConfig(
		c.cfg,
		func(options *elasticloadbalancingv2.Options) {
			options.Region = region
		},
	)
	regionRef := regionPointer(region)
	count := 0
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(
		client,
		&elasticloadbalancingv2.DescribeLoadBalancersInput{},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, loadBalancer := range page.LoadBalancers {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(loadBalancer)
			if err != nil {
				c.addError(
					sourceType,
					"elasticloadbalancingv2.DescribeLoadBalancers.encode",
					regionRef,
					err,
				)
				continue
			}
			c.addResource(sourceType, addRegion(raw, region))
			count++
		}
	}
	c.completeScope(
		sourceType,
		"elasticloadbalancingv2.DescribeLoadBalancers",
		regionRef,
		count,
		collectionErr,
	)
}

func (c *Collector) collectSecrets(ctx context.Context, region string) {
	const sourceType = "aws.secretsmanager.secret"
	client := secretsmanager.NewFromConfig(c.cfg, func(options *secretsmanager.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := secretsmanager.NewListSecretsPaginator(
		client,
		&secretsmanager.ListSecretsInput{},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, secret := range page.SecretList {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(secret)
			if err != nil {
				c.addError(sourceType, "secretsmanager.ListSecrets.encode", regionRef, err)
				continue
			}
			raw["Region"] = region
			raw["PublicPolicy"] = false
			secretID := aws.ToString(secret.ARN)
			if secretID == "" {
				secretID = aws.ToString(secret.Name)
			}
			if output, err := client.GetResourcePolicy(
				ctx,
				&secretsmanager.GetResourcePolicyInput{SecretId: aws.String(secretID)},
			); err == nil {
				raw["PublicPolicy"] = hasWildcardPrincipal(aws.ToString(output.ResourcePolicy))
			}
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "secretsmanager.ListSecrets", regionRef, count, collectionErr)
}

func (c *Collector) collectRedshift(ctx context.Context, region string) {
	const sourceType = "aws.redshift.cluster"
	client := redshift.NewFromConfig(c.cfg, func(options *redshift.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, cluster := range page.Clusters {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(cluster)
			if err != nil {
				c.addError(sourceType, "redshift.DescribeClusters.encode", regionRef, err)
				continue
			}
			c.addResource(sourceType, addRegion(raw, region))
			count++
		}
	}
	c.completeScope(sourceType, "redshift.DescribeClusters", regionRef, count, collectionErr)
}

func (c *Collector) collectNeptune(ctx context.Context, region string) {
	const sourceType = "aws.neptune.cluster"
	client := neptune.NewFromConfig(c.cfg, func(options *neptune.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := neptune.NewDescribeDBClustersPaginator(
		client,
		&neptune.DescribeDBClustersInput{},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, cluster := range page.DBClusters {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(cluster)
			if err != nil {
				c.addError(sourceType, "neptune.DescribeDBClusters.encode", regionRef, err)
				continue
			}
			c.addResource(sourceType, addRegion(raw, region))
			count++
		}
	}
	c.completeScope(sourceType, "neptune.DescribeDBClusters", regionRef, count, collectionErr)
}

func (c *Collector) collectDocDB(ctx context.Context, region string) {
	const sourceType = "aws.docdb.cluster"
	client := docdb.NewFromConfig(c.cfg, func(options *docdb.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := docdb.NewDescribeDBClustersPaginator(
		client,
		&docdb.DescribeDBClustersInput{},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, cluster := range page.DBClusters {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(cluster)
			if err != nil {
				c.addError(sourceType, "docdb.DescribeDBClusters.encode", regionRef, err)
				continue
			}
			c.addResource(sourceType, addRegion(raw, region))
			count++
		}
	}
	c.completeScope(sourceType, "docdb.DescribeDBClusters", regionRef, count, collectionErr)
}

func (c *Collector) collectECS(ctx context.Context, region string) {
	const sourceType = "aws.ecs.cluster"
	client := ecs.NewFromConfig(c.cfg, func(options *ecs.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	arns := make([]string, 0)
	paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	var collectionErr error
	for paginator.HasMorePages() && len(arns) < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		remaining := c.maxItems - len(arns)
		if len(page.ClusterArns) > remaining {
			arns = append(arns, page.ClusterArns[:remaining]...)
			break
		}
		arns = append(arns, page.ClusterArns...)
	}

	count := 0
	if collectionErr == nil {
		for start := 0; start < len(arns); start += 100 {
			end := min(start+100, len(arns))
			output, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
				Clusters: arns[start:end],
				Include: []ecstypes.ClusterField{
					ecstypes.ClusterFieldSettings,
					ecstypes.ClusterFieldTags,
				},
			})
			if err != nil {
				collectionErr = err
				break
			}
			if len(output.Failures) > 0 {
				collectionErr = fmt.Errorf(
					"ecs.DescribeClusters returned %d resource failures",
					len(output.Failures),
				)
			}
			for _, cluster := range output.Clusters {
				raw := mapECSCluster(cluster, region)
				c.addResource(sourceType, raw)
				count++
			}
		}
	}
	c.completeScope(
		sourceType,
		"ecs.ListClusters+DescribeClusters",
		regionRef,
		count,
		collectionErr,
	)
}

func mapECSCluster(cluster ecstypes.Cluster, region string) map[string]any {
	settings := make([]map[string]any, 0, len(cluster.Settings))
	for _, setting := range cluster.Settings {
		settings = append(settings, map[string]any{
			"name":  string(setting.Name),
			"value": aws.ToString(setting.Value),
		})
	}
	tags := make([]map[string]any, 0, len(cluster.Tags))
	for _, tag := range cluster.Tags {
		tags = append(tags, map[string]any{
			"key":   aws.ToString(tag.Key),
			"value": aws.ToString(tag.Value),
		})
	}
	return map[string]any{
		"clusterArn":                        aws.ToString(cluster.ClusterArn),
		"clusterName":                       aws.ToString(cluster.ClusterName),
		"status":                            aws.ToString(cluster.Status),
		"registeredContainerInstancesCount": cluster.RegisteredContainerInstancesCount,
		"runningTasksCount":                 cluster.RunningTasksCount,
		"pendingTasksCount":                 cluster.PendingTasksCount,
		"activeServicesCount":               cluster.ActiveServicesCount,
		"capacityProviders":                 cluster.CapacityProviders,
		"settings":                          settings,
		"tags":                              tags,
		"Region":                            region,
	}
}

func (c *Collector) collectCloudTrail(ctx context.Context) {
	const sourceType = "aws.cloudtrail.trail"
	client := cloudtrail.NewFromConfig(c.cfg, func(options *cloudtrail.Options) {
		options.Region = c.request.HomeRegion
	})
	output, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		c.completeScope(sourceType, "cloudtrail.DescribeTrails", nil, 0, err)
		return
	}
	count := 0
	for _, trail := range output.TrailList {
		if count >= c.maxItems {
			break
		}
		raw, err := toMap(trail)
		if err != nil {
			c.addError(sourceType, "cloudtrail.DescribeTrails.encode", nil, err)
			continue
		}
		raw["Region"] = "global"
		raw["IsLogging"] = false
		name := aws.ToString(trail.TrailARN)
		if name == "" {
			name = aws.ToString(trail.Name)
		}
		if status, err := client.GetTrailStatus(
			ctx,
			&cloudtrail.GetTrailStatusInput{Name: aws.String(name)},
		); err == nil {
			raw["IsLogging"] = status.IsLogging
		}
		c.addResource(sourceType, raw)
		count++
	}
	c.completeScope(sourceType, "cloudtrail.DescribeTrails", nil, count, nil)
}

func (c *Collector) collectConfig(ctx context.Context, region string) {
	const sourceType = "aws.config.recorder"
	client := configservice.NewFromConfig(c.cfg, func(options *configservice.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	output, err := client.DescribeConfigurationRecorders(
		ctx,
		&configservice.DescribeConfigurationRecordersInput{},
	)
	if err != nil {
		c.completeScope(
			sourceType,
			"configservice.DescribeConfigurationRecorders",
			regionRef,
			0,
			err,
		)
		return
	}
	count := 0
	for _, recorder := range output.ConfigurationRecorders {
		if count >= c.maxItems {
			break
		}
		raw := map[string]any{
			"name":         aws.ToString(recorder.Name),
			"roleARN":      aws.ToString(recorder.RoleARN),
			"_IsRecording": false,
			"Region":       region,
		}
		if recorder.RecordingGroup != nil {
			raw["recordingGroup"] = map[string]any{
				"allSupported":               recorder.RecordingGroup.AllSupported,
				"includeGlobalResourceTypes": recorder.RecordingGroup.IncludeGlobalResourceTypes,
				"resourceTypes":              recorder.RecordingGroup.ResourceTypes,
			}
		}
		name := aws.ToString(recorder.Name)
		statuses, statusErr := client.DescribeConfigurationRecorderStatus(
			ctx,
			&configservice.DescribeConfigurationRecorderStatusInput{
				ConfigurationRecorderNames: []string{name},
			},
		)
		if statusErr == nil && len(statuses.ConfigurationRecordersStatus) > 0 {
			raw["_IsRecording"] = statuses.ConfigurationRecordersStatus[0].Recording
		}
		c.addResource(sourceType, raw)
		count++
	}
	c.completeScope(
		sourceType,
		"configservice.DescribeConfigurationRecorders",
		regionRef,
		count,
		nil,
	)
}

func (c *Collector) collectKMS(ctx context.Context, region string) {
	const sourceType = "aws.kms.key"
	client := kms.NewFromConfig(c.cfg, func(options *kms.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, key := range page.Keys {
			if count >= c.maxItems {
				break
			}
			raw, err := toMap(key)
			if err != nil {
				c.addError(sourceType, "kms.ListKeys.encode", regionRef, err)
				continue
			}
			raw["Region"] = region
			raw["KeyState"] = nil
			raw["KeyManager"] = nil
			raw["KeySpec"] = nil
			raw["RotationEnabled"] = false
			raw["RotationChecked"] = false
			keyID := aws.ToString(key.KeyId)
			if output, err := client.DescribeKey(
				ctx,
				&kms.DescribeKeyInput{KeyId: aws.String(keyID)},
			); err == nil && output.KeyMetadata != nil {
				metadata := output.KeyMetadata
				raw["KeyState"] = string(metadata.KeyState)
				raw["KeyManager"] = string(metadata.KeyManager)
				raw["KeySpec"] = string(metadata.KeySpec)
				if string(metadata.KeyManager) == "CUSTOMER" &&
					string(metadata.KeyState) == "Enabled" {
					if rotation, err := client.GetKeyRotationStatus(
						ctx,
						&kms.GetKeyRotationStatusInput{KeyId: aws.String(keyID)},
					); err == nil {
						raw["RotationEnabled"] = rotation.KeyRotationEnabled
						raw["RotationChecked"] = true
					}
				}
			}
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "kms.ListKeys", regionRef, count, collectionErr)
}

func (c *Collector) collectLogGroups(ctx context.Context, region string) {
	const sourceType = "aws.cloudwatch.log_group"
	client := cloudwatchlogs.NewFromConfig(c.cfg, func(options *cloudwatchlogs.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)
	count := 0
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(
		client,
		&cloudwatchlogs.DescribeLogGroupsInput{},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, group := range page.LogGroups {
			if count >= c.maxItems {
				break
			}
			raw := map[string]any{
				"logGroupName":    aws.ToString(group.LogGroupName),
				"arn":             aws.ToString(group.Arn),
				"kmsKeyId":        aws.ToString(group.KmsKeyId),
				"retentionInDays": group.RetentionInDays,
				"storedBytes":     group.StoredBytes,
				"creationTime":    group.CreationTime,
				"Region":          region,
			}
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(
		sourceType,
		"cloudwatchlogs.DescribeLogGroups",
		regionRef,
		count,
		collectionErr,
	)
}
