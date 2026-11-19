package cloudwatch

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// countingEC2Client records DescribeInstances calls. Rejected attribute names must
// be refused before that call: the handler uses the returned Instance value to
// decide whether an attribute path is safe, so a lookup that runs first is the
// use the check is supposed to prevent.
type countingEC2Client struct {
	oldEC2Client
	describeCalls int
}

func (c *countingEC2Client) DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	c.describeCalls++
	return c.oldEC2Client.DescribeInstances(ctx, in, optFns...)
}

func TestEc2InstanceAttributeQueryIsConstrained(t *testing.T) {
	origNewEC2API := NewEC2API
	t.Cleanup(func() {
		NewEC2API = origNewEC2API
	})

	var cli *countingEC2Client
	NewEC2API = func(aws.Config) models.EC2APIProvider {
		return cli
	}
	ds := newTestDatasource()

	useInstances := func(instances ...ec2types.Instance) {
		t.Helper()
		cli = &countingEC2Client{oldEC2Client: oldEC2Client{
			reservations: []ec2types.Reservation{{Instances: instances}},
		}}
	}

	call := func(t *testing.T, attributeName string) *backend.CallResourceResponse {
		t.Helper()
		sender := &mockedCallResourceResponseSenderForOauth{}
		query := url.Values{}
		query.Set("region", "us-east-1")
		query.Set("attributeName", attributeName)
		query.Set("filters", "{}")
		req := &backend.CallResourceRequest{
			Method: http.MethodGet,
			Path:   "ec2-instance-attribute",
			URL:    "ec2-instance-attribute?" + query.Encode(),
			PluginContext: backend.PluginContext{
				PluginID:                   "cloudwatch",
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
			},
		}
		require.NotPanics(t, func() {
			err := ds.CallResource(context.Background(), req, sender)
			require.NoError(t, err)
		})
		require.NotNil(t, sender.Response)
		return sender.Response
	}

	rejected := func(t *testing.T, attributeName string, instances ...ec2types.Instance) {
		t.Helper()
		useInstances(instances...)
		resp := call(t, attributeName)
		assert.Equal(t, http.StatusBadRequest, resp.Status, "body: %s", resp.Body)
		assert.Zero(t, cli.describeCalls, "DescribeInstances ran before the attribute name was refused")
	}

	// Tags are fully populated here so a nil-tag panic cannot mask the reflection panic.
	instance := ec2types.Instance{
		InstanceId: aws.String("i-12345678"),
		Placement: &ec2types.Placement{
			AvailabilityZone: aws.String("us-east-1a"),
		},
		State:              &ec2types.InstanceState{},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/app")},
		Tags: []ec2types.Tag{
			{Key: aws.String("Name"), Value: aws.String("web")},
		},
	}
	nilTagInstance := instance
	nilTagInstance.Tags = []ec2types.Tag{
		{Key: nil, Value: aws.String("missing-key")},
		{Key: aws.String("Environment"), Value: nil},
		{Key: aws.String("Name"), Value: aws.String("web")},
	}

	t.Run("rejects the unexported embedded EC2 field", func(t *testing.T) {
		rejected(t, "noSmithyDocumentSerde", instance)
	})

	t.Run("rejects an unexported field reached through Placement", func(t *testing.T) {
		rejected(t, "Placement.noSmithyDocumentSerde", instance)
	})

	t.Run("rejects an unexported field reached through State", func(t *testing.T) {
		rejected(t, "State.noSmithyDocumentSerde", instance)
	})

	t.Run("rejects an unexported field reached through IamInstanceProfile", func(t *testing.T) {
		rejected(t, "IamInstanceProfile.noSmithyDocumentSerde", instance)
	})

	t.Run("rejects an unknown attribute when the account has an instance", func(t *testing.T) {
		rejected(t, "NotARealField", instance)
	})

	t.Run("rejects an unexported attribute when the account has no instances", func(t *testing.T) {
		rejected(t, "noSmithyDocumentSerde")
	})

	t.Run("rejects an unknown attribute when the account has no instances", func(t *testing.T) {
		rejected(t, "NotARealField")
	})

	t.Run("returns an exported attribute from the same instance", func(t *testing.T) {
		useInstances(nilTagInstance)
		resp := call(t, "InstanceId")
		require.Equal(t, http.StatusOK, resp.Status, "body: %s", resp.Body)
		assert.Equal(t, 1, cli.describeCalls)
		assert.JSONEq(t, `[{"text":"i-12345678","value":"i-12345678","label":"i-12345678"}]`, string(resp.Body))
	})

	t.Run("returns an exported nested attribute and not the unexported sibling", func(t *testing.T) {
		useInstances(nilTagInstance)
		resp := call(t, "Placement.AvailabilityZone")
		require.Equal(t, http.StatusOK, resp.Status, "body: %s", resp.Body)
		assert.Equal(t, 1, cli.describeCalls)
		assert.JSONEq(t, `[{"text":"us-east-1a","value":"us-east-1a","label":"us-east-1a"}]`, string(resp.Body))
	})

	t.Run("returns a nested profile ARN", func(t *testing.T) {
		useInstances(nilTagInstance)
		resp := call(t, "IamInstanceProfile.Arn")
		require.Equal(t, http.StatusOK, resp.Status, "body: %s", resp.Body)
		assert.JSONEq(t, `[{"text":"arn:aws:iam::123456789012:instance-profile/app","value":"arn:aws:iam::123456789012:instance-profile/app","label":"arn:aws:iam::123456789012:instance-profile/app"}]`, string(resp.Body))
	})

	t.Run("skips nil tag keys and values and still returns the named tag", func(t *testing.T) {
		useInstances(nilTagInstance)
		resp := call(t, "Tags.Name")
		require.Equal(t, http.StatusOK, resp.Status, "body: %s", resp.Body)
		assert.Equal(t, 1, cli.describeCalls)
		assert.JSONEq(t, `[{"text":"web","value":"web","label":"web"}]`, string(resp.Body))
	})

	t.Run("skips a tag whose value is nil", func(t *testing.T) {
		useInstances(nilTagInstance)
		resp := call(t, "Tags.Environment")
		require.Equal(t, http.StatusOK, resp.Status, "body: %s", resp.Body)
		assert.NotContains(t, string(resp.Body), "missing-key")
		// A nil value is skipped, so the tag is absent. An absent tag is reported
		// as an empty suggestion, which is the same result as a tag the instance
		// does not have.
		assert.JSONEq(t, `[{"text":"","value":"","label":""}]`, string(resp.Body))
	})
}
