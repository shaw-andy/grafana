package cloudwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
)

type suggestData struct {
	Text  string `json:"text"`
	Value string `json:"value"`
	Label string `json:"label"`
}

func parseMultiSelectValue(input string) []string {
	trimmedInput := strings.TrimSpace(input)
	if strings.HasPrefix(trimmedInput, "{") {
		values := strings.Split(strings.TrimRight(strings.TrimLeft(trimmedInput, "{"), "}"), ",")
		trimmedValues := make([]string, len(values))
		for i, v := range values {
			trimmedValues[i] = strings.TrimSpace(v)
		}
		return trimmedValues
	}

	return []string{trimmedInput}
}

func (ds *DataSource) handleGetEbsVolumeIds(ctx context.Context, parameters url.Values) ([]suggestData, error) {
	region := parameters.Get("region")
	instanceId := parameters.Get("instanceId")

	instanceIds := parseMultiSelectValue(instanceId)
	instances, err := ds.ec2DescribeInstances(ctx, region, nil, instanceIds)
	if err != nil {
		return nil, err
	}

	result := make([]suggestData, 0)
	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			for _, mapping := range instance.BlockDeviceMappings {
				if mapping.Ebs == nil || mapping.Ebs.VolumeId == nil {
					continue
				}
				result = append(result, suggestData{Text: *mapping.Ebs.VolumeId, Value: *mapping.Ebs.VolumeId, Label: *mapping.Ebs.VolumeId})
			}
		}
	}

	return result, nil
}

func (ds *DataSource) handleGetEc2InstanceAttribute(ctx context.Context, parameters url.Values) ([]suggestData, error) {
	region := parameters.Get("region")
	attribute, err := parseInstanceAttribute(parameters.Get("attributeName"))
	if err != nil {
		return nil, err
	}
	filterJson := parameters.Get("filters")

	filterMap := map[string]any{}
	err = json.Unmarshal([]byte(filterJson), &filterMap)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling filter: %v", err)
	}

	var filters []ec2types.Filter
	for k, v := range filterMap {
		if vv, ok := v.([]any); ok {
			var values []string
			for _, vvv := range vv {
				if vvvv, ok := vvv.(string); ok {
					values = append(values, vvvv)
				}
			}
			filters = append(filters, ec2types.Filter{
				Name:   aws.String(k),
				Values: values,
			})
		}
	}

	instances, err := ds.ec2DescribeInstances(ctx, region, filters, nil)
	if err != nil {
		return nil, err
	}

	result := make([]suggestData, 0)
	dupCheck := make(map[string]bool)
	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			data, found, err := getInstanceAttributeValue(attribute, instance)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if _, exists := dupCheck[data]; exists {
				continue
			}

			dupCheck[data] = true
			result = append(result, suggestData{Text: data, Value: data, Label: data})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Text < result[j].Text
	})

	return result, nil
}

// ec2InstanceAttributePaths maps every attribute name a query may ask for to the
// field index path in ec2types.Instance. It is built from the type, not from
// returned instances, so unexported or embedded fields (such as the SDK's
// noSmithyDocumentSerde) can never be selected.
var ec2InstanceAttributePaths = buildInstanceAttributePaths(reflect.TypeFor[ec2types.Instance]())

func buildInstanceAttributePaths(root reflect.Type) map[string][]int {
	timeType := reflect.TypeFor[time.Time]()
	paths := make(map[string][]int)
	seen := map[reflect.Type]bool{root: true}

	var walk func(t reflect.Type, prefix string, index []int)
	walk = func(t reflect.Type, prefix string, index []int) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() || field.Anonymous {
				continue
			}
			name := prefix + field.Name
			fieldIndex := append(slices.Clone(index), i)
			if isSupportedInstanceAttributeType(field.Type) {
				paths[name] = fieldIndex
				continue
			}
			nested := field.Type
			if nested.Kind() == reflect.Pointer {
				nested = nested.Elem()
			}
			if nested.Kind() != reflect.Struct || nested == timeType || seen[nested] {
				continue
			}
			seen[nested] = true
			walk(nested, name+".", fieldIndex)
			delete(seen, nested)
		}
	}
	walk(root, "", nil)
	return paths
}

func isSupportedInstanceAttributeType(t reflect.Type) bool {
	if t.Kind() == reflect.String {
		return true
	}
	if t.Kind() != reflect.Pointer {
		return false
	}
	switch t.Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	}
	return t == reflect.TypeFor[*string]() || t == reflect.TypeFor[*time.Time]() || t == reflect.TypeFor[*bool]()
}

type instanceAttribute struct {
	isTag      bool
	tagName    string
	fieldIndex []int
}

func parseInstanceAttribute(attributeName string) (instanceAttribute, error) {
	if tagName, ok := strings.CutPrefix(attributeName, "Tags."); ok {
		return instanceAttribute{isTag: true, tagName: tagName}, nil
	}
	fieldIndex, ok := ec2InstanceAttributePaths[attributeName]
	if !ok {
		return instanceAttribute{}, errors.New("invalid attribute path")
	}
	return instanceAttribute{fieldIndex: fieldIndex}, nil
}

func getInstanceAttributeValue(attribute instanceAttribute, instance ec2types.Instance) (value string, found bool, err error) {
	if attribute.isTag {
		tags := make(map[string]string)
		for _, tag := range instance.Tags {
			if tag.Key == nil || tag.Value == nil {
				continue
			}
			tags[*tag.Key] = *tag.Value
		}
		return tags[attribute.tagName], true, nil
	}

	v := reflect.ValueOf(instance)
	for _, i := range attribute.fieldIndex {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return "", false, nil
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}

	if !v.CanInterface() {
		return "", false, errors.New("invalid attribute path")
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return "", false, nil
	}
	if v.Kind() == reflect.String {
		if v.String() == "" {
			return "", false, nil
		}
		return v.String(), true, nil
	}

	switch attr := v.Interface().(type) {
	case *string:
		return *attr, true, nil
	case *time.Time:
		return attr.String(), true, nil
	case *bool:
		return fmt.Sprint(*attr), true, nil
	}
	if v.Kind() == reflect.Pointer && v.Elem().CanInt() {
		return fmt.Sprint(v.Elem().Int()), true, nil
	}
	return "", false, errors.New("cannot parse attribute")
}

func (ds *DataSource) handleGetResourceArns(ctx context.Context, parameters url.Values) ([]suggestData, error) {
	region := parameters.Get("region")
	resourceType := parameters.Get("resourceType")
	tagsJson := parameters.Get("tags")

	tagsMap := map[string]any{}
	err := json.Unmarshal([]byte(tagsJson), &tagsMap)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling filter: %v", err)
	}

	var filters []resourcegroupstaggingapitypes.TagFilter
	for k, v := range tagsMap {
		if vv, ok := v.([]any); ok {
			var values []string
			for _, vvv := range vv {
				if vvvv, ok := vvv.(string); ok {
					values = append(values, vvvv)
				}
			}
			filters = append(filters, resourcegroupstaggingapitypes.TagFilter{
				Key:    aws.String(k),
				Values: values,
			})
		}
	}

	resourceTypes := []string{resourceType}

	resources, err := ds.resourceGroupsGetResources(ctx, region, filters, resourceTypes)
	if err != nil {
		return nil, err
	}

	result := make([]suggestData, 0)
	for _, resource := range resources.ResourceTagMappingList {
		if resource.ResourceARN == nil {
			continue
		}
		data := *resource.ResourceARN
		result = append(result, suggestData{Text: data, Value: data, Label: data})
	}

	return result, nil
}

func (ds *DataSource) ec2DescribeInstances(ctx context.Context, region string, filters []ec2types.Filter, instanceIds []string) (*ec2.DescribeInstancesOutput, error) {
	params := &ec2.DescribeInstancesInput{
		Filters:     filters,
		InstanceIds: instanceIds,
	}

	client, err := ds.getEC2Client(ctx, region)
	if err != nil {
		return nil, err
	}

	resp := &ec2.DescribeInstancesOutput{}
	pager := ec2.NewDescribeInstancesPaginator(client, params)
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return resp, fmt.Errorf("describe instances pager failed: %w", err)
		}
		resp.Reservations = append(resp.Reservations, page.Reservations...)
	}
	return resp, nil
}

func (ds *DataSource) resourceGroupsGetResources(ctx context.Context, region string, filters []resourcegroupstaggingapitypes.TagFilter,
	resourceTypes []string) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	params := &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: resourceTypes,
		TagFilters:          filters,
	}

	client, err := ds.getRGTAClient(ctx, region)
	if err != nil {
		return nil, err
	}

	var resp resourcegroupstaggingapi.GetResourcesOutput
	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(client, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get resource groups paginator failed: %w", err)
		}
		resp.ResourceTagMappingList = append(resp.ResourceTagMappingList, page.ResourceTagMappingList...)
	}

	return &resp, nil
}

// legacy route, will be removed once GovCloud supports Cross Account Observability
func (ds *DataSource) handleGetLogGroups(ctx context.Context, parameters url.Values) ([]suggestData, error) {
	region := parameters.Get("region")
	limit := parameters.Get("limit")
	logGroupNamePrefix := parameters.Get("logGroupNamePrefix")

	logsClient, err := ds.getCWLogsClient(ctx, region)
	if err != nil {
		return nil, err
	}

	logGroupLimit := defaultLogGroupLimit
	intLimit, err := strconv.ParseInt(limit, 10, 32)
	if err == nil && intLimit > 0 {
		logGroupLimit = int32(intLimit)
	}

	input := &cloudwatchlogs.DescribeLogGroupsInput{Limit: aws.Int32(logGroupLimit)}
	if len(logGroupNamePrefix) > 0 {
		input.LogGroupNamePrefix = aws.String(logGroupNamePrefix)
	}
	var response *cloudwatchlogs.DescribeLogGroupsOutput
	response, err = logsClient.DescribeLogGroups(ctx, input)
	if err != nil || response == nil {
		return nil, err
	}
	result := make([]suggestData, 0)
	for _, logGroup := range response.LogGroups {
		if logGroup.LogGroupName == nil {
			continue
		}
		logGroupName := *logGroup.LogGroupName
		result = append(result, suggestData{Text: logGroupName, Value: logGroupName, Label: logGroupName})
	}

	return result, nil
}
