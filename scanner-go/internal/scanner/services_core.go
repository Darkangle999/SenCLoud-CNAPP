package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (c *Collector) collectEC2(ctx context.Context, region string) {
	client := ec2.NewFromConfig(c.cfg, func(options *ec2.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)

	instanceCount := 0
	instancePaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	var instanceErr error
	for instancePaginator.HasMorePages() && instanceCount < c.maxItems {
		page, err := instancePaginator.NextPage(ctx)
		if err != nil {
			instanceErr = err
			break
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instanceCount >= c.maxItems {
					break
				}
				raw, err := toMap(instance)
				if err != nil {
					c.addError("aws.ec2.instance", "ec2.DescribeInstances.encode", regionRef, err)
					continue
				}
				c.addResource("aws.ec2.instance", addRegion(raw, region))
				instanceCount++
			}
		}
	}
	c.completeScope(
		"aws.ec2.instance",
		"ec2.DescribeInstances",
		regionRef,
		instanceCount,
		instanceErr,
	)

	groupCount := 0
	groupPaginator := ec2.NewDescribeSecurityGroupsPaginator(
		client,
		&ec2.DescribeSecurityGroupsInput{},
	)
	var groupErr error
	for groupPaginator.HasMorePages() && groupCount < c.maxItems {
		page, err := groupPaginator.NextPage(ctx)
		if err != nil {
			groupErr = err
			break
		}
		for _, group := range page.SecurityGroups {
			if groupCount >= c.maxItems {
				break
			}
			raw, err := toMap(group)
			if err != nil {
				c.addError(
					"aws.ec2.security_group",
					"ec2.DescribeSecurityGroups.encode",
					regionRef,
					err,
				)
				continue
			}
			c.addResource("aws.ec2.security_group", addRegion(raw, region))
			groupCount++
		}
	}
	c.completeScope(
		"aws.ec2.security_group",
		"ec2.DescribeSecurityGroups",
		regionRef,
		groupCount,
		groupErr,
	)

	// Network control-plane evidence is collected alongside workloads. It is
	// required to prove public reachability instead of treating a public endpoint
	// flag as an exploitable path.
	c.collectEC2Network(ctx, client, region)
}

func (c *Collector) collectEC2Network(ctx context.Context, client *ec2.Client, region string) {
	regionRef := regionPointer(region)

	subnetCount := 0
	subnetPaginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	var subnetErr error
	for subnetPaginator.HasMorePages() && subnetCount < c.maxItems {
		page, err := subnetPaginator.NextPage(ctx)
		if err != nil {
			subnetErr = err
			break
		}
		for _, subnet := range page.Subnets {
			if subnetCount >= c.maxItems {
				break
			}
			c.addEC2NetworkResource("aws.ec2.subnet", "ec2.DescribeSubnets", regionRef, subnet, region)
			subnetCount++
		}
	}
	c.completeScope("aws.ec2.subnet", "ec2.DescribeSubnets", regionRef, subnetCount, subnetErr)

	routeTableCount := 0
	routeTablePaginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	var routeTableErr error
	for routeTablePaginator.HasMorePages() && routeTableCount < c.maxItems {
		page, err := routeTablePaginator.NextPage(ctx)
		if err != nil {
			routeTableErr = err
			break
		}
		for _, routeTable := range page.RouteTables {
			if routeTableCount >= c.maxItems {
				break
			}
			c.addEC2NetworkResource("aws.ec2.route_table", "ec2.DescribeRouteTables", regionRef, routeTable, region)
			routeTableCount++
		}
	}
	c.completeScope("aws.ec2.route_table", "ec2.DescribeRouteTables", regionRef, routeTableCount, routeTableErr)

	aclCount := 0
	aclPaginator := ec2.NewDescribeNetworkAclsPaginator(client, &ec2.DescribeNetworkAclsInput{})
	var aclErr error
	for aclPaginator.HasMorePages() && aclCount < c.maxItems {
		page, err := aclPaginator.NextPage(ctx)
		if err != nil {
			aclErr = err
			break
		}
		for _, acl := range page.NetworkAcls {
			if aclCount >= c.maxItems {
				break
			}
			c.addEC2NetworkResource("aws.ec2.network_acl", "ec2.DescribeNetworkAcls", regionRef, acl, region)
			aclCount++
		}
	}
	c.completeScope("aws.ec2.network_acl", "ec2.DescribeNetworkAcls", regionRef, aclCount, aclErr)

	gatewayCount := 0
	gatewayPaginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})
	var gatewayErr error
	for gatewayPaginator.HasMorePages() && gatewayCount < c.maxItems {
		page, err := gatewayPaginator.NextPage(ctx)
		if err != nil {
			gatewayErr = err
			break
		}
		for _, gateway := range page.InternetGateways {
			if gatewayCount >= c.maxItems {
				break
			}
			c.addEC2NetworkResource("aws.ec2.internet_gateway", "ec2.DescribeInternetGateways", regionRef, gateway, region)
			gatewayCount++
		}
	}
	c.completeScope("aws.ec2.internet_gateway", "ec2.DescribeInternetGateways", regionRef, gatewayCount, gatewayErr)

	interfaceCount := 0
	interfacePaginator := ec2.NewDescribeNetworkInterfacesPaginator(client, &ec2.DescribeNetworkInterfacesInput{})
	var interfaceErr error
	for interfacePaginator.HasMorePages() && interfaceCount < c.maxItems {
		page, err := interfacePaginator.NextPage(ctx)
		if err != nil {
			interfaceErr = err
			break
		}
		for _, networkInterface := range page.NetworkInterfaces {
			if interfaceCount >= c.maxItems {
				break
			}
			c.addEC2NetworkResource(
				"aws.ec2.network_interface",
				"ec2.DescribeNetworkInterfaces",
				regionRef,
				networkInterface,
				region,
			)
			interfaceCount++
		}
	}
	c.completeScope(
		"aws.ec2.network_interface",
		"ec2.DescribeNetworkInterfaces",
		regionRef,
		interfaceCount,
		interfaceErr,
	)
}

func (c *Collector) addEC2NetworkResource(
	sourceType string,
	operation string,
	regionRef *string,
	resource any,
	region string,
) {
	raw, err := toMap(resource)
	if err != nil {
		c.addError(sourceType, operation+".encode", regionRef, err)
		return
	}
	c.addResource(sourceType, addRegion(raw, region))
}

func (c *Collector) collectS3(ctx context.Context) {
	const sourceType = "aws.s3.bucket"
	client := s3.NewFromConfig(c.cfg, func(options *s3.Options) {
		options.Region = c.request.HomeRegion
	})
	count := 0
	paginator := s3.NewListBucketsPaginator(
		client,
		&s3.ListBucketsInput{MaxBuckets: aws.Int32(1000)},
	)
	var collectionErr error
	for paginator.HasMorePages() && count < c.maxItems {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			collectionErr = err
			break
		}
		for _, bucket := range page.Buckets {
			if count >= c.maxItems {
				break
			}
			raw, encodeErr := toMap(bucket)
			if encodeErr != nil {
				c.addError(sourceType, "s3.ListBuckets.encode", nil, encodeErr)
				continue
			}
			c.enrichS3Bucket(ctx, client, raw)
			c.addResource(sourceType, raw)
			count++
		}
	}
	c.completeScope(sourceType, "s3.ListBuckets", nil, count, collectionErr)
}

func (c *Collector) enrichS3Bucket(
	ctx context.Context,
	homeClient *s3.Client,
	raw map[string]any,
) {
	name, _ := raw["Name"].(string)
	if name == "" {
		return
	}

	region, _ := raw["BucketRegion"].(string)
	if region == "" {
		region = "us-east-1"
	}
	if location, err := homeClient.GetBucketLocation(
		ctx,
		&s3.GetBucketLocationInput{Bucket: aws.String(name)},
	); err == nil {
		region = string(location.LocationConstraint)
		if region == "" {
			region = "us-east-1"
		} else if region == "EU" {
			region = "eu-west-1"
		}
	}
	raw["Region"] = region
	client := s3.NewFromConfig(c.cfg, func(options *s3.Options) {
		options.Region = region
	})

	raw["PublicAccessBlock"] = map[string]any{}
	if output, err := client.GetPublicAccessBlock(
		ctx,
		&s3.GetPublicAccessBlockInput{Bucket: aws.String(name)},
	); err == nil && output.PublicAccessBlockConfiguration != nil {
		if value, mapErr := toMap(output.PublicAccessBlockConfiguration); mapErr == nil {
			raw["PublicAccessBlock"] = value
		}
	}

	raw["PolicyStatus"] = map[string]any{}
	if output, err := client.GetBucketPolicyStatus(
		ctx,
		&s3.GetBucketPolicyStatusInput{Bucket: aws.String(name)},
	); err == nil && output.PolicyStatus != nil {
		if value, mapErr := toMap(output.PolicyStatus); mapErr == nil {
			raw["PolicyStatus"] = value
		}
	}

	raw["Acl"] = map[string]any{}
	if output, err := client.GetBucketAcl(
		ctx,
		&s3.GetBucketAclInput{Bucket: aws.String(name)},
	); err == nil {
		if value, mapErr := toMap(output); mapErr == nil {
			raw["Acl"] = value
		}
	}

	raw["Encryption"] = map[string]any{"enabled": false, "algorithm": nil}
	if output, err := client.GetBucketEncryption(
		ctx,
		&s3.GetBucketEncryptionInput{Bucket: aws.String(name)},
	); err == nil && output.ServerSideEncryptionConfiguration != nil &&
		len(output.ServerSideEncryptionConfiguration.Rules) > 0 {
		defaultEncryption := output.ServerSideEncryptionConfiguration.Rules[0].
			ApplyServerSideEncryptionByDefault
		if defaultEncryption != nil {
			algorithm := string(defaultEncryption.SSEAlgorithm)
			raw["Encryption"] = map[string]any{
				"enabled":   algorithm != "",
				"algorithm": algorithm,
			}
		}
	}

	raw["Versioning"] = nil
	if output, err := client.GetBucketVersioning(
		ctx,
		&s3.GetBucketVersioningInput{Bucket: aws.String(name)},
	); err == nil {
		raw["Versioning"] = string(output.Status)
	}

	raw["Policy"] = false
	if output, err := client.GetBucketPolicy(
		ctx,
		&s3.GetBucketPolicyInput{Bucket: aws.String(name)},
	); err == nil {
		raw["Policy"] = strings.TrimSpace(aws.ToString(output.Policy)) != ""
	}

	raw["Tags"] = map[string]string{}
	if output, err := client.GetBucketTagging(
		ctx,
		&s3.GetBucketTaggingInput{Bucket: aws.String(name)},
	); err == nil {
		tags := make(map[string]string, len(output.TagSet))
		for _, tag := range output.TagSet {
			if tag.Key != nil {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}
		raw["Tags"] = tags
	}
}

func (c *Collector) collectRDS(ctx context.Context, region string) {
	client := rds.NewFromConfig(c.cfg, func(options *rds.Options) {
		options.Region = region
	})
	regionRef := regionPointer(region)

	instanceCount := 0
	instancePaginator := rds.NewDescribeDBInstancesPaginator(
		client,
		&rds.DescribeDBInstancesInput{},
	)
	var instanceErr error
	for instancePaginator.HasMorePages() && instanceCount < c.maxItems {
		page, err := instancePaginator.NextPage(ctx)
		if err != nil {
			instanceErr = err
			break
		}
		for _, instance := range page.DBInstances {
			if instanceCount >= c.maxItems {
				break
			}
			raw, err := toMap(instance)
			if err != nil {
				c.addError("aws.rds.db_instance", "rds.DescribeDBInstances.encode", regionRef, err)
				continue
			}
			c.addResource("aws.rds.db_instance", addRegion(raw, region))
			instanceCount++
		}
	}
	c.completeScope(
		"aws.rds.db_instance",
		"rds.DescribeDBInstances",
		regionRef,
		instanceCount,
		instanceErr,
	)

	clusterCount := 0
	clusterPaginator := rds.NewDescribeDBClustersPaginator(
		client,
		&rds.DescribeDBClustersInput{},
	)
	var clusterErr error
	for clusterPaginator.HasMorePages() && clusterCount < c.maxItems {
		page, err := clusterPaginator.NextPage(ctx)
		if err != nil {
			clusterErr = err
			break
		}
		for _, cluster := range page.DBClusters {
			if clusterCount >= c.maxItems {
				break
			}
			raw, err := toMap(cluster)
			if err != nil {
				c.addError("aws.rds.db_cluster", "rds.DescribeDBClusters.encode", regionRef, err)
				continue
			}
			c.addResource("aws.rds.db_cluster", addRegion(raw, region))
			clusterCount++
		}
	}
	c.completeScope(
		"aws.rds.db_cluster",
		"rds.DescribeDBClusters",
		regionRef,
		clusterCount,
		clusterErr,
	)

	proxyCount := 0
	proxyPaginator := rds.NewDescribeDBProxiesPaginator(
		client,
		&rds.DescribeDBProxiesInput{},
	)
	var proxyErr error
	for proxyPaginator.HasMorePages() && proxyCount < c.maxItems {
		page, err := proxyPaginator.NextPage(ctx)
		if err != nil {
			proxyErr = err
			break
		}
		for _, proxy := range page.DBProxies {
			if proxyCount >= c.maxItems {
				break
			}
			raw, err := toMap(proxy)
			if err != nil {
				c.addError("aws.rds.db_proxy", "rds.DescribeDBProxies.encode", regionRef, err)
				continue
			}
			c.addResource("aws.rds.db_proxy", addRegion(raw, region))
			proxyCount++
		}
	}
	c.completeScope(
		"aws.rds.db_proxy",
		"rds.DescribeDBProxies",
		regionRef,
		proxyCount,
		proxyErr,
	)
}

func hasWildcardPrincipal(document string) bool {
	if strings.TrimSpace(document) == "" {
		return false
	}
	var policy map[string]any
	if json.Unmarshal([]byte(document), &policy) != nil {
		return false
	}
	for _, statement := range statements(policy) {
		if statement["Effect"] != "Allow" {
			continue
		}
		principal := statement["Principal"]
		if principal == "*" {
			return true
		}
		principalMap, ok := principal.(map[string]any)
		if !ok {
			continue
		}
		for _, candidate := range stringsFrom(principalMap["AWS"]) {
			if candidate == "*" {
				return true
			}
		}
	}
	return false
}

func encodeError(operation string, err error) error {
	return fmt.Errorf("%s response could not be encoded: %w", operation, err)
}
