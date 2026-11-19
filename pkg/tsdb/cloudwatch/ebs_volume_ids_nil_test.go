package cloudwatch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// TestCallResource_EBSVolumeIDs_SkipsBlockDevicesWithoutVolumeID drives the
// ebs-volume-ids resource with a DescribeInstances body the AWS SDK decodes
// itself. Instance-store mappings omit the ebs element, and an ebs element can
// omit volumeId. Both are nil pointers. The handler must return only volumes
// that are present.
func TestCallResource_EBSVolumeIDs_SkipsBlockDevicesWithoutVolumeID(t *testing.T) {
	const (
		region        = "us-east-1"
		instanceID    = "i-store"
		otherID       = "i-other"
		pageToken     = "page-2"
		presentVolume = "vol-present"
		laterVolume   = "vol-later"
	)

	mappings := blockDeviceMapping(
		// Instance-store volume: device name only, no ebs element.
		`<item><deviceName>/dev/sdb</deviceName></item>`,
		// EBS object present, volume id omitted.
		`<item><deviceName>/dev/sdc</deviceName><ebs><status>attached</status><deleteOnTermination>false</deleteOnTermination></ebs></item>`,
		// Volume that must still be returned.
		`<item><deviceName>/dev/sdd</deviceName><ebs><volumeId>`+laterVolume+`</volumeId><status>attached</status></ebs></item>`,
	)
	pages := map[string]string{
		"":        describeInstancesResponse(pageToken, instanceXML(instanceID, blockDeviceMapping(`<item><deviceName>/dev/sda1</deviceName><ebs><volumeId>`+presentVolume+`</volumeId><status>attached</status></ebs></item>`))),
		pageToken: describeInstancesResponse("", instanceXML(instanceID, mappings)+instanceXML(otherID, blockDeviceMapping(`<item><deviceName>/dev/sdb</deviceName></item>`))),
	}

	for _, tc := range []struct {
		name       string
		instanceID string
		wantIDs    []string
	}{
		{
			name:       "single instance id",
			instanceID: instanceID,
			wantIDs:    []string{instanceID},
		},
		{
			name:       "multi-select instance ids",
			instanceID: "{" + instanceID + ", " + otherID + "}",
			wantIDs:    []string{instanceID, otherID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				form, err := url.ParseQuery(string(body))
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				for key, values := range r.URL.Query() {
					for _, value := range values {
						form.Add(key, value)
					}
				}
				mu.Lock()
				requests = append(requests, form)
				mu.Unlock()

				w.Header().Set("Content-Type", "text/xml")
				page := pages[form.Get("NextToken")]
				if page == "" && form.Get("NextToken") != "" {
					http.Error(w, "unknown page", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, page)
			}))
			t.Cleanup(srv.Close)

			origNewEC2API := NewEC2API
			t.Cleanup(func() { NewEC2API = origNewEC2API })
			NewEC2API = func(cfg aws.Config) models.EC2APIProvider {
				if cfg.Region == "" {
					cfg.Region = region
				}
				return ec2.NewFromConfig(cfg, func(o *ec2.Options) {
					o.BaseEndpoint = aws.String(srv.URL)
				})
			}

			ds := newTestDatasource()
			sender := &mockedCallResourceResponseSenderForOauth{}
			err := ds.CallResource(context.Background(), &backend.CallResourceRequest{
				Method: http.MethodGet,
				Path:   "/ebs-volume-ids?region=" + region + "&instanceId=" + url.QueryEscape(tc.instanceID),
				PluginContext: backend.PluginContext{
					PluginID: "cloudwatch",
				},
			}, sender)

			require.NoError(t, err)
			require.NotNil(t, sender.Response)
			require.Equal(t, http.StatusOK, sender.Response.Status, string(sender.Response.Body))

			var got []suggestData
			require.NoError(t, json.Unmarshal(sender.Response.Body, &got))
			require.Equal(t, []suggestData{
				{Text: presentVolume, Value: presentVolume, Label: presentVolume},
				{Text: laterVolume, Value: laterVolume, Label: laterVolume},
			}, got)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, requests, 2)
			require.Equal(t, "DescribeInstances", requests[0].Get("Action"))
			require.Empty(t, requests[0].Get("NextToken"))
			require.ElementsMatch(t, tc.wantIDs, instanceIDs(requests[0]))
			require.Equal(t, "DescribeInstances", requests[1].Get("Action"))
			require.Equal(t, pageToken, requests[1].Get("NextToken"))
			require.ElementsMatch(t, tc.wantIDs, instanceIDs(requests[1]))
		})
	}
}

func instanceIDs(form url.Values) []string {
	var ids []string
	for key, values := range form {
		if strings.HasPrefix(key, "InstanceId.") {
			ids = append(ids, values...)
		}
	}
	return ids
}

func describeInstancesResponse(nextToken, instances string) string {
	token := ""
	if nextToken != "" {
		token = "<nextToken>" + nextToken + "</nextToken>"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>req-ebs</requestId>
  ` + token + `
  <reservationSet>
    <item>
      <reservationId>r-ebs</reservationId>
      <ownerId>000000000000</ownerId>
      <instancesSet>` + instances + `</instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`
}

func instanceXML(instanceID, mappings string) string {
	return `<item><instanceId>` + instanceID + `</instanceId>` + mappings + `</item>`
}

func blockDeviceMapping(items ...string) string {
	body := "<blockDeviceMapping>"
	for _, item := range items {
		body += item
	}
	return body + "</blockDeviceMapping>"
}
