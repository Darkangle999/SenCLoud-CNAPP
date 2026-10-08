package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/odineyes/odineyes/scanner/internal/protocol"
)

const (
	defaultWorkers  = 16
	defaultMaxItems = 5000
)

type Collector struct {
	cfg         aws.Config
	request     protocol.ScanRequest
	regions     []string
	maxWorkers  int
	maxItems    int
	startedAt   time.Time
	operations  atomic.Int64
	mu          sync.Mutex
	resources   []protocol.RawResource
	scopes      []protocol.Scope
	errors      []protocol.CollectionError
	scopeKeys   map[string]struct{}
	resourceIDs map[string]struct{}
}

func New(ctx context.Context, request protocol.ScanRequest) (*Collector, error) {
	cfg, err := loadAccountConfig(
		ctx,
		request.AccountIdentifier,
		request.RoleARN,
		request.ExternalID,
		request.HomeRegion,
	)
	if err != nil {
		return nil, err
	}
	workers := request.MaxWorkers
	if workers == 0 {
		workers = defaultWorkers
	}
	maxItems := request.MaxItems
	if maxItems == 0 {
		maxItems = defaultMaxItems
	}
	return &Collector{
		cfg:         cfg,
		request:     request,
		maxWorkers:  workers,
		maxItems:    maxItems,
		startedAt:   time.Now(),
		scopeKeys:   make(map[string]struct{}),
		resourceIDs: make(map[string]struct{}),
	}, nil
}

type collectionTask struct {
	name string
	run  func(context.Context)
}

func (c *Collector) Collect(ctx context.Context) protocol.ScanResponse {
	c.regions = append([]string(nil), c.request.Regions...)
	if len(c.regions) == 0 {
		c.regions = c.discoverRegions(ctx)
	}
	c.regions = filterExcludedRegions(uniqueSorted(c.regions), c.request.ExcludedRegions)
	if len(c.regions) == 0 {
		c.regions = filterExcludedRegions([]string{c.request.HomeRegion}, c.request.ExcludedRegions)
	}
	if len(c.regions) == 0 {
		// Everything was excluded: still scan the home region so the request
		// cannot turn into a silent no-op that ages stored assets out.
		c.regions = []string{c.request.HomeRegion}
	}

	tasks := []collectionTask{
		{name: "s3", run: c.collectS3},
		{name: "iam", run: c.collectIAM},
		{name: "cloudtrail", run: c.collectCloudTrail},
	}
	for _, region := range c.regions {
		region := region
		tasks = append(tasks,
			collectionTask{name: "ec2@" + region, run: func(ctx context.Context) { c.collectEC2(ctx, region) }},
			collectionTask{name: "rds@" + region, run: func(ctx context.Context) { c.collectRDS(ctx, region) }},
			collectionTask{name: "lambda@" + region, run: func(ctx context.Context) { c.collectLambda(ctx, region) }},
			collectionTask{name: "elbv2@" + region, run: func(ctx context.Context) { c.collectLoadBalancers(ctx, region) }},
			collectionTask{name: "secretsmanager@" + region, run: func(ctx context.Context) { c.collectSecrets(ctx, region) }},
			collectionTask{name: "redshift@" + region, run: func(ctx context.Context) { c.collectRedshift(ctx, region) }},
			collectionTask{name: "neptune@" + region, run: func(ctx context.Context) { c.collectNeptune(ctx, region) }},
			collectionTask{name: "docdb@" + region, run: func(ctx context.Context) { c.collectDocDB(ctx, region) }},
			collectionTask{name: "ecs@" + region, run: func(ctx context.Context) { c.collectECS(ctx, region) }},
			collectionTask{name: "config@" + region, run: func(ctx context.Context) { c.collectConfig(ctx, region) }},
			collectionTask{name: "kms@" + region, run: func(ctx context.Context) { c.collectKMS(ctx, region) }},
			collectionTask{name: "logs@" + region, run: func(ctx context.Context) { c.collectLogGroups(ctx, region) }},
		)
	}

	taskCh := make(chan collectionTask)
	var workers sync.WaitGroup
	workerCount := min(c.maxWorkers, len(tasks))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range taskCh {
				select {
				case <-ctx.Done():
					return
				default:
					slog.Debug("running AWS collection task", "task", task.name)
					task.run(ctx)
				}
			}
		}()
	}
submitTasks:
	for _, task := range tasks {
		select {
		case taskCh <- task:
		case <-ctx.Done():
			break submitTasks
		}
	}
	close(taskCh)
	workers.Wait()
	if err := ctx.Err(); err != nil {
		c.addError("aws.scan", "scan.context", nil, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Slice(c.resources, func(i, j int) bool {
		if c.resources[i].SourceType != c.resources[j].SourceType {
			return c.resources[i].SourceType < c.resources[j].SourceType
		}
		return stableResourceKey(c.resources[i].Raw) < stableResourceKey(c.resources[j].Raw)
	})
	sort.Slice(c.scopes, func(i, j int) bool {
		if c.scopes[i].SourceType != c.scopes[j].SourceType {
			return c.scopes[i].SourceType < c.scopes[j].SourceType
		}
		return stringValue(c.scopes[i].Region) < stringValue(c.scopes[j].Region)
	})
	byType := make(map[string]int)
	for _, resource := range c.resources {
		byType[resource.SourceType]++
	}
	return protocol.ScanResponse{
		SchemaVersion:     protocol.SchemaVersion,
		Collector:         "odineyes-go-aws/v1",
		AccountIdentifier: c.request.AccountIdentifier,
		Resources:         c.resources,
		Authoritative:     c.scopes,
		Errors:            c.errors,
		Metrics: protocol.Metrics{
			RegionsScanned: len(c.regions),
			Operations:     int(c.operations.Load()),
			Resources:      len(c.resources),
			ByType:         byType,
			DurationMS:     time.Since(c.startedAt).Milliseconds(),
		},
	}
}

func (c *Collector) discoverRegions(ctx context.Context) []string {
	c.operations.Add(1)
	client := ec2.NewFromConfig(c.cfg, func(options *ec2.Options) {
		options.Region = c.request.HomeRegion
	})
	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		Filters: []ec2types.Filter{{
			Name: aws.String("opt-in-status"),
			Values: []string{
				"opt-in-not-required",
				"opted-in",
			},
		}},
	})
	if err != nil {
		c.addError(
			"aws.region",
			"ec2.DescribeRegions",
			regionPointer(c.request.HomeRegion),
			fmt.Errorf("region discovery failed; scanning home region only: %w", err),
		)
		return filterExcludedRegions([]string{c.request.HomeRegion}, c.request.ExcludedRegions)
	}
	regions := make([]string, 0, len(output.Regions))
	for _, region := range output.Regions {
		if value := aws.ToString(region.RegionName); value != "" {
			regions = append(regions, value)
		}
	}
	return filterExcludedRegions(regions, c.request.ExcludedRegions)
}

// filterExcludedRegions drops operator-excluded regions (e.g. ones an SCP
// blocks) from a sweep set while preserving order.
func filterExcludedRegions(regions, excluded []string) []string {
	if len(excluded) == 0 || len(regions) == 0 {
		return regions
	}
	blocked := make(map[string]struct{}, len(excluded))
	for _, region := range excluded {
		blocked[region] = struct{}{}
	}
	kept := make([]string, 0, len(regions))
	for _, region := range regions {
		if _, skip := blocked[region]; !skip {
			kept = append(kept, region)
		}
	}
	return kept
}

func (c *Collector) addResource(sourceType string, raw map[string]any) {
	if sourceType == "" || len(raw) == 0 {
		return
	}
	key := sourceType + "|" + stableResourceKey(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.resourceIDs[key]; exists {
		return
	}
	c.resourceIDs[key] = struct{}{}
	c.resources = append(c.resources, protocol.RawResource{SourceType: sourceType, Raw: raw})
}

func (c *Collector) addScope(sourceType string, region *string) {
	key := sourceType + "|" + stringValue(region)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.scopeKeys[key]; exists {
		return
	}
	c.scopeKeys[key] = struct{}{}
	c.scopes = append(c.scopes, protocol.Scope{SourceType: sourceType, Region: region})
}

func (c *Collector) addError(sourceType, operation string, region *string, err error) {
	message := "unknown collection error"
	if err != nil {
		message = err.Error()
	}
	if len(message) > 2000 {
		message = message[:2000]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, protocol.CollectionError{
		SourceType: sourceType,
		Operation:  operation,
		Message:    message,
		Region:     region,
	})
}

func (c *Collector) completeScope(sourceType, operation string, region *string, count int, err error) bool {
	c.operations.Add(1)
	if err != nil {
		c.addError(sourceType, operation, region, err)
		return false
	}
	if count >= c.maxItems {
		c.addError(
			sourceType,
			operation,
			region,
			fmt.Errorf("result reached the %d-item safety limit", c.maxItems),
		)
		return false
	}
	if c.hasErrorForScope(sourceType, region) {
		return false
	}
	c.addScope(sourceType, region)
	return true
}

func (c *Collector) hasErrorForScope(sourceType string, region *string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, collectionError := range c.errors {
		if collectionError.SourceType == sourceType &&
			stringValue(collectionError.Region) == stringValue(region) {
			return true
		}
	}
	return false
}

func toMap(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func addRegion(raw map[string]any, region string) map[string]any {
	raw["Region"] = region
	return raw
}

func regionPointer(region string) *string {
	value := region
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stableResourceKey(raw map[string]any) string {
	for _, key := range []string{
		"Arn", "ARN", "RoleName", "UserName", "InstanceId", "GroupId", "Name",
		"DBInstanceArn", "DBClusterArn", "DBProxyArn", "FunctionArn",
		"LoadBalancerArn", "ClusterIdentifier", "ClusterArn", "clusterArn",
		"TrailARN", "KeyArn", "arn", "logGroupName",
	} {
		if value, ok := raw[key]; ok {
			return fmt.Sprint(value)
		}
	}
	data, _ := json.Marshal(raw)
	return string(data)
}
