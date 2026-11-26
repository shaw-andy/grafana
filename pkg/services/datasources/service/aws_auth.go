package service

import (
	"encoding/json"
	"slices"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/components/simplejson"
)

const cloudWatchPluginID = "cloudwatch"

// awsDefaultAuthType is what the AWS SDK falls back to when an auth type is missing or empty,
// and what CloudWatch resolves the legacy "arn" value and any unknown value to.
const awsDefaultAuthType = "default"

var errAWSAuthProviderNotAllowed = errutil.ValidationFailed("datasource.awsAuthProviderNotAllowed",
	errutil.WithPublicMessage("The AWS authentication provider is not allowed by the [aws] allowed_auth_providers setting."))

// validateAWSAuthProviders refuses a data source whose AWS auth type is not in
// allowed_auth_providers. The auth type is resolved the same way the AWS SDK resolves it at
// query time, so a missing or legacy value counts as the SDK default chain.
func (s *Service) validateAWSAuthProviders(dsType string, jsonData *simplejson.Json) error {
	if jsonData == nil {
		jsonData = simplejson.New()
	}

	if dsType == cloudWatchPluginID {
		authType, err := cloudWatchAuthType(jsonData)
		if err != nil || !slices.Contains(s.cfg.AWSAllowedAuthProviders, authType) {
			return errAWSAuthProviderNotAllowed.Errorf("authType %q is not an allowed AWS auth provider", authType)
		}
	}

	if jsonData.Get("sigV4Auth").MustBool(false) {
		authType := jsonData.Get("sigV4AuthType").MustString()
		if authType == "" {
			authType = awsDefaultAuthType
		}
		if !slices.Contains(s.cfg.AWSAllowedAuthProviders, authType) {
			return errAWSAuthProviderNotAllowed.Errorf("sigV4AuthType %q is not an allowed AWS auth provider", authType)
		}
	}

	return nil
}

// setAWSAuthProviderForEmptyCloudWatch gives a CloudWatch data source created without any
// settings (as the "Add data source" page does) the first allowed auth provider, so it does not
// resolve to the SDK default chain when that chain is not allowed.
func (s *Service) setAWSAuthProviderForEmptyCloudWatch(dsType string, jsonData *simplejson.Json) {
	if dsType != cloudWatchPluginID || jsonData == nil || len(jsonData.MustMap()) > 0 {
		return
	}
	if len(s.cfg.AWSAllowedAuthProviders) == 0 || slices.Contains(s.cfg.AWSAllowedAuthProviders, awsDefaultAuthType) {
		return
	}
	jsonData.Set("authType", s.cfg.AWSAllowedAuthProviders[0])
}

func cloudWatchAuthType(jsonData *simplejson.Json) (string, error) {
	raw, ok := jsonData.CheckGet("authType")
	if !ok {
		return awsDefaultAuthType, nil
	}
	encoded, err := raw.MarshalJSON()
	if err != nil {
		return awsDefaultAuthType, err
	}
	var authType awsds.AuthType
	if err := json.Unmarshal(encoded, &authType); err != nil {
		return awsDefaultAuthType, err
	}
	return authType.String(), nil
}
