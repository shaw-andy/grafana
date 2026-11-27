package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/web"
)

var endpoints = map[string]map[string]string{
	"cortex": {
		"silences": "/alertmanager/api/v2/silences",
		"silence":  "/alertmanager/api/v2/silence/%s",
		"status":   "/alertmanager/api/v2/status",
		"groups":   "/alertmanager/api/v2/alerts/groups",
		"alerts":   "/alertmanager/api/v2/alerts",
		"config":   "/api/v1/alerts",
	},
	"mimir": {
		"silences": "/alertmanager/api/v2/silences",
		"silence":  "/alertmanager/api/v2/silence/%s",
		"status":   "/alertmanager/api/v2/status",
		"groups":   "/alertmanager/api/v2/alerts/groups",
		"alerts":   "/alertmanager/api/v2/alerts",
		"config":   "/api/v1/alerts",
	},
	"prometheus": {
		"silences": "/api/v2/silences",
		"silence":  "/api/v2/silence/%s",
		"status":   "/api/v2/status",
		"groups":   "/api/v2/alerts/groups",
		"alerts":   "/api/v2/alerts",
	},
}

const (
	defaultImplementation = "cortex"
)

type LotexAM struct {
	log log.Logger
	*AlertingProxy
}

func NewLotexAM(proxy *AlertingProxy, log log.Logger) *LotexAM {
	return &LotexAM{
		log:           log,
		AlertingProxy: proxy,
	}
}

func (am *LotexAM) withAMReq(
	ctx *contextmodel.ReqContext,
	method string,
	endpoint string,
	pathParams []string,
	body io.Reader,
	extractor func(*response.NormalResponse) (interface{}, error),
	headers map[string]string,
) response.Response {
	datasourceUID := web.Params(ctx.Req)[":DatasourceUID"]
	if datasourceUID == "" {
		return response.Error(http.StatusBadRequest, "DatasourceUID is invalid", nil)
	}

	ds, err := am.DataProxy.DataSourceCache.GetDatasourceByUID(ctx.Req.Context(), datasourceUID, ctx.SignedInUser, ctx.SkipDSCache)
	if err != nil {
		if errors.Is(err, datasources.ErrDataSourceAccessDenied) {
			return ErrResp(http.StatusForbidden, err, "Access denied to datasource")
		}
		if errors.Is(err, datasources.ErrDataSourceNotFound) {
			return ErrResp(http.StatusNotFound, err, "Unable to find datasource")
		}
		return ErrResp(http.StatusInternalServerError, err, "Unable to load datasource meta data")
	}

	impl := ds.JsonData.Get("implementation").MustString(defaultImplementation)
	implEndpoints, ok := endpoints[impl]
	if !ok {
		return ErrResp(http.StatusBadRequest, fmt.Errorf("unsupported Alert Manager implementation \"%s\"", impl), "")
	}
	endpointPath, ok := implEndpoints[endpoint]
	if !ok {
		return ErrResp(http.StatusBadRequest, fmt.Errorf("unsupported endpoint \"%s\" for Alert Manager implementation \"%s\"", endpoint, impl), "")
	}

	iPathParams := make([]interface{}, len(pathParams))
	for idx, value := range pathParams {
		iPathParams[idx] = value
	}

	return am.withReq(
		ctx,
		method,
		withPath(*ctx.Req.URL, fmt.Sprintf(endpointPath, iPathParams...)),
		body,
		extractor,
		headers,
	)
}

func (am *LotexAM) RouteGetAMStatus(ctx *contextmodel.ReqContext) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodGet,
		"status",
		nil,
		nil,
		jsonExtractor(&apimodels.ExternalAlertmanagerStatus{}),
		nil,
	)
}

func (am *LotexAM) RouteCreateSilence(ctx *contextmodel.ReqContext, silenceBody apimodels.PostableSilence) response.Response {
	blob, err := json.Marshal(silenceBody)
	if err != nil {
		return ErrResp(500, err, "Failed marshal silence")
	}
	return am.withAMReq(
		ctx,
		http.MethodPost,
		"silences",
		nil,
		bytes.NewBuffer(blob),
		jsonExtractor(&apimodels.PostSilencesOKBody{}),
		map[string]string{"Content-Type": "application/json"},
	)
}

func (am *LotexAM) RouteDeleteAlertingConfig(ctx *contextmodel.ReqContext) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodDelete,
		"config",
		nil,
		nil,
		messageExtractor,
		nil,
	)
}

func (am *LotexAM) RouteDeleteSilence(ctx *contextmodel.ReqContext, silenceID string) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodDelete,
		"silence",
		[]string{silenceID},
		nil,
		messageExtractor,
		nil,
	)
}

func (am *LotexAM) RouteGetAlertingConfig(ctx *contextmodel.ReqContext) response.Response {
	datasourceUID := web.Params(ctx.Req)[":DatasourceUID"]
	if datasourceUID == "" {
		return response.Error(http.StatusBadRequest, "DatasourceUID is invalid", nil)
	}
	writeEval := accesscontrol.EvalPermission(accesscontrol.ActionAlertingNotificationsExternalWrite, datasources.ScopeProvider.GetResourceScopeUID(datasourceUID))

	canWrite := false
	if am.ac != nil {
		var err error
		canWrite, err = am.ac.Evaluate(ctx.Req.Context(), ctx.SignedInUser, writeEval)
		if err != nil {
			return ErrResp(http.StatusInternalServerError, err, "Failed to evaluate permissions")
		}
	}

	// The upstream config contains receiver secrets in plain text. Only callers that can
	// write the config get it verbatim, because posting it back requires the real values.
	if canWrite {
		return am.withAMReq(
			ctx,
			http.MethodGet,
			"config",
			nil,
			nil,
			yamlExtractor(&apimodels.ExternalAlertmanagerConfig{}),
			nil,
		)
	}

	return am.withAMReq(
		withExternalConfigRouteGrant(ctx, datasourceUID),
		http.MethodGet,
		"config",
		nil,
		nil,
		redactedExternalConfigExtractor,
		nil,
	)
}

func redactedExternalConfigExtractor(resp *response.NormalResponse) (any, error) {
	cfg := &apimodels.ExternalAlertmanagerConfig{}
	if _, err := yamlExtractor(cfg)(resp); err != nil {
		return nil, err
	}
	return cfg.WithRedactedSecrets()
}

// withExternalConfigRouteGrant returns a copy of ctx whose requester passes the Alertmanager
// plugin route for the raw config on the given datasource. That route requires write access
// so the datasource proxy never hands the unredacted config to read-only users. The copy is
// only used for the fixed upstream GET issued here, and its response is redacted before it
// is returned.
func withExternalConfigRouteGrant(ctx *contextmodel.ReqContext, datasourceUID string) *contextmodel.ReqContext {
	u := *ctx.SignedInUser
	perms := make(map[int64]map[string][]string, len(u.Permissions)+1)
	for orgID, orgPerms := range u.Permissions {
		perms[orgID] = maps.Clone(orgPerms)
	}
	if perms[u.OrgID] == nil {
		perms[u.OrgID] = map[string][]string{}
	}
	action := accesscontrol.ActionAlertingNotificationsExternalWrite
	perms[u.OrgID][action] = append(slices.Clone(perms[u.OrgID][action]), datasources.ScopeProvider.GetResourceScopeUID(datasourceUID))
	u.Permissions = perms

	webCtx := *ctx.Context
	webCtx.Req = ctx.Req.WithContext(identity.WithRequester(ctx.Req.Context(), &u))
	cpy := *ctx
	cpy.Context = &webCtx
	cpy.SignedInUser = &u
	return &cpy
}

func (am *LotexAM) RouteGetAMAlertGroups(ctx *contextmodel.ReqContext) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodGet,
		"groups",
		nil,
		nil,
		jsonExtractor(&apimodels.AlertGroups{}),
		nil,
	)
}

func (am *LotexAM) RouteGetAMAlerts(ctx *contextmodel.ReqContext) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodGet,
		"alerts",
		nil,
		nil,
		jsonExtractor(&apimodels.GettableAlerts{}),
		nil,
	)
}

func (am *LotexAM) RouteGetSilence(ctx *contextmodel.ReqContext, silenceID string) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodGet,
		"silence",
		[]string{silenceID},
		nil,
		jsonExtractor(&apimodels.GettableSilence{}),
		nil,
	)
}

func (am *LotexAM) RouteGetSilences(ctx *contextmodel.ReqContext) response.Response {
	return am.withAMReq(
		ctx,
		http.MethodGet,
		"silences",
		nil,
		nil,
		jsonExtractor(&apimodels.GettableSilences{}),
		nil,
	)
}

func (am *LotexAM) RoutePostAlertingConfig(ctx *contextmodel.ReqContext, config apimodels.ExternalAlertmanagerConfig) response.Response {
	yml, err := yaml.Marshal(&config)
	if err != nil {
		return ErrResp(500, err, "Failed marshal alert manager configuration ")
	}

	return am.withAMReq(
		ctx,
		http.MethodPost,
		"config",
		nil,
		bytes.NewBuffer(yml),
		messageExtractor,
		nil,
	)
}

func (am *LotexAM) RoutePostAMAlerts(ctx *contextmodel.ReqContext, alerts apimodels.PostableAlerts) response.Response {
	yml, err := yaml.Marshal(alerts)
	if err != nil {
		return ErrResp(500, err, "Failed marshal postable alerts")
	}

	return am.withAMReq(
		ctx,
		http.MethodPost,
		"alerts",
		nil,
		bytes.NewBuffer(yml),
		messageExtractor,
		nil,
	)
}
