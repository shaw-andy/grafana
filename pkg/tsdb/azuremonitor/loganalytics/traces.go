package loganalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/macros"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/utils"
)

type TraceQueries struct {
	TraceExploreQuery       string
	TraceParentExploreQuery string
	TraceLogsExploreQuery   string
}

var (
	kqlIdentifierRegExp     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	kqlPropertyPathRegExp   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	kqlVerbatimStringEscape = strings.NewReplacer(
		"'", "''",
		// KqlInterpolate expands macros anywhere in the query text, including inside
		// string literals, so "$__" is split across adjacent (concatenated) literals.
		"$__", "$'@'__",
		// Verbatim literals cannot contain line breaks, so these are emitted as
		// adjacent escaped literals.
		"\n", `'"\n"@'`,
		"\r", `'"\r"@'`,
	)
)

// kqlString returns s as a Kusto verbatim string literal.
func kqlString(s string) string {
	return "@'" + kqlVerbatimStringEscape.Replace(s) + "'"
}

// kqlPropertyReference returns a column reference for a trace filter property.
// Bracket-quoted identifiers use regular string literal rules, so characters that
// could end the literal or start a macro are refused rather than escaped. Kusto
// identifiers never contain them.
func kqlPropertyReference(property string) (string, error) {
	if kqlPropertyPathRegExp.MatchString(property) {
		return property, nil
	}
	if property == "" || strings.ContainsAny(property, `'"\$`) || strings.IndexFunc(property, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("invalid trace filter property %q", property)
	}
	return "['" + property + "']", nil
}

func buildTracesQuery(operationId string, parentSpanID *string, traceTypes []string, filters []dataquery.AzureTracesFilter, resultFormat *dataquery.ResultFormat, resources []string) (string, error) {
	types := traceTypes
	if len(types) == 0 {
		types = Tables
	}
	for _, t := range types {
		if !kqlIdentifierRegExp.MatchString(t) {
			return "", fmt.Errorf("invalid trace type %q", t)
		}
	}

	filteredTypes := make([]string, 0)
	// If the result format is set to trace then we filter out all events that are of the type traces as they don't make sense when visualised as a span
	if resultFormat != nil && *resultFormat == dataquery.ResultFormatTrace {
		// k8s slices.Filter has been deprecated in favor of stdlib slices.DeleteFunc,
		// but slices.DeleteFunc mutates the underlying slice, which we don't want to do.
		// Instead, just iterate over the original slice and apply our filter function to get the new one.
		// (this is exactly what k8s's slices.Filter did/does)
		for _, s := range types {
			if s != "traces" {
				filteredTypes = append(filteredTypes, s)
			}
		}
	} else {
		filteredTypes = types
	}
	sort.Strings(filteredTypes)

	if len(filteredTypes) == 0 {
		return "", nil
	}

	resourcesQuery := strings.Join(filteredTypes, ",")
	if len(resources) > 0 {
		intermediate := make([]string, 0)
		for _, resource := range resources {
			for _, table := range filteredTypes {
				intermediate = append(intermediate, fmt.Sprintf("app(%s).%s", kqlString(resource), table))
			}
		}
		resourcesQuery += "," + strings.Join(intermediate, ",")
	}

	tagsMap := make(map[string]bool)
	var tags []string
	for _, t := range filteredTypes {
		tableTags := getTagsForTable(t)
		for _, i := range tableTags {
			if tagsMap[i] {
				continue
			}
			if i == "cloud_RoleInstance" || i == "cloud_RoleName" || i == "customDimensions" || i == "customMeasurements" {
				continue
			}
			tags = append(tags, i)
			tagsMap[i] = true
		}
	}
	sort.Strings(tags)

	whereClause := ""

	if operationId != "" {
		quotedOperationId := kqlString(operationId)
		whereClause = fmt.Sprintf("| where (operation_Id != '' and operation_Id == %s) or (customDimensions.ai_legacyRootId != '' and customDimensions.ai_legacyRootId == %s)", quotedOperationId, quotedOperationId)
	}

	parentWhereClause := ""
	if parentSpanID != nil && *parentSpanID != "" {
		parentWhereClause = fmt.Sprintf("| where (operation_ParentId != '' and operation_ParentId == %s)", kqlString(*parentSpanID))
	}

	filtersClause := ""

	if len(filters) > 0 {
		for _, filter := range filters {
			if len(filter.Filters) == 0 {
				continue
			}
			property, err := kqlPropertyReference(filter.Property)
			if err != nil {
				return "", err
			}
			operation := "in"
			if filter.Operation == "ne" {
				operation = "!in"
			}
			filterValues := []string{}
			for _, val := range filter.Filters {
				filterValues = append(filterValues, kqlString(val))
			}
			filtersClause += fmt.Sprintf("| where %s %s (%s)", property, operation, strings.Join(filterValues, ","))
		}
	}

	propertiesFunc := "bag_merge(customDimensions, customMeasurements)"
	if len(tags) > 0 {
		propertiesFunc = fmt.Sprintf("bag_merge(bag_pack_columns(%s), customDimensions, customMeasurements)", strings.Join(tags, ","))
	}

	errorProperty := `| extend error = todynamic(iff(itemType == "exception", "true", "false"))`

	baseQuery := fmt.Sprintf(`set truncationmaxrecords=10000; set truncationmaxsize=67108864; union isfuzzy=true %s`, resourcesQuery)
	propertiesStaticQuery := `| extend duration = iff(isnull(column_ifexists("duration", real(null))), toreal(0), column_ifexists("duration", real(null)))` +
		`| extend spanID = iff(itemType == "pageView" or isempty(column_ifexists("id", "")), tostring(new_guid()), column_ifexists("id", ""))` +
		`| extend operationName = iff(isempty(column_ifexists("name", "")), column_ifexists("problemId", ""), column_ifexists("name", ""))` +
		`| extend serviceName = cloud_RoleName` +
		`| extend serviceTags = bag_pack_columns(cloud_RoleInstance, cloud_RoleName)`
	propertiesQuery := fmt.Sprintf(`| extend tags = %s`, propertiesFunc)
	projectClause := `| project-rename traceID = operation_Id, parentSpanID = operation_ParentId, startTime = timestamp, resource = _ResourceId` +
		`| project startTime, itemType, serviceName, duration, traceID, spanID, parentSpanID, operationName, serviceTags, tags, itemId, resource` +
		`| order by startTime asc`
	return baseQuery + whereClause + parentWhereClause + propertiesStaticQuery + errorProperty + propertiesQuery + filtersClause + projectClause, nil
}

func buildTracesLogsQuery(operationId string, resources []string) string {
	types := Tables
	sort.Strings(types)
	selectors := "union " + strings.Join(types, ",\n") + "\n"
	if len(resources) > 0 {
		intermediate := make([]string, 0, len(resources)*len(types))
		for _, resource := range resources {
			for _, table := range types {
				intermediate = append(intermediate, fmt.Sprintf("app(%s).%s", kqlString(resource), table))
			}
		}
		sort.Strings(intermediate)
		types = intermediate
		selectors = strings.Join(append([]string{"union *"}, types...), ",\n") + "\n"
	}

	query := selectors
	query += fmt.Sprintf(`| where operation_Id == %s`, kqlString(operationId))
	return query
}

func buildTraceQueries(query backend.DataQuery, dsInfo types.DatasourceInfo, tracesQuery dataquery.AzureTracesQuery, operationId string, resultFormat dataquery.ResultFormat, queryResources []string) (string, *TraceQueries, error) {
	traceExploreQuery := ""
	traceParentExploreQuery := ""
	traceLogsExploreQuery := ""
	traceIdVariable := "${__data.fields.traceID}"
	parentSpanIdVariable := "${__data.fields.parentSpanID}"
	var err error

	traceQueries := TraceQueries{}

	queryString, err := buildTracesQuery(operationId, nil, tracesQuery.TraceTypes, tracesQuery.Filters, &resultFormat, queryResources)
	if err != nil {
		return "", &traceQueries, err
	}

	if operationId == "" {
		traceExploreQuery, err = buildTracesQuery(traceIdVariable, nil, tracesQuery.TraceTypes, tracesQuery.Filters, &resultFormat, queryResources)
		if err != nil {
			return "", &traceQueries, err
		}
		traceParentExploreQuery, err = buildTracesQuery(traceIdVariable, &parentSpanIdVariable, tracesQuery.TraceTypes, tracesQuery.Filters, &resultFormat, queryResources)
		if err != nil {
			return "", &traceQueries, err
		}
		traceLogsExploreQuery = buildTracesLogsQuery(traceIdVariable, queryResources)
	} else {
		traceExploreQuery = queryString
		traceParentExploreQuery, err = buildTracesQuery(operationId, &parentSpanIdVariable, tracesQuery.TraceTypes, tracesQuery.Filters, &resultFormat, queryResources)
		if err != nil {
			return "", &traceQueries, err
		}
		traceLogsExploreQuery = buildTracesLogsQuery(operationId, queryResources)
	}

	traceExploreQuery, err = macros.KqlInterpolate(query, dsInfo, traceExploreQuery, "TimeGenerated")
	if err != nil {
		return "", &traceQueries, fmt.Errorf("failed to create traces explore query: %s", err)
	}
	traceQueries.TraceExploreQuery = traceExploreQuery

	traceParentExploreQuery, err = macros.KqlInterpolate(query, dsInfo, traceParentExploreQuery, "TimeGenerated")
	if err != nil {
		return "", &traceQueries, fmt.Errorf("failed to create parent span traces explore query: %s", err)
	}
	traceQueries.TraceParentExploreQuery = traceParentExploreQuery

	traceLogsExploreQuery, err = macros.KqlInterpolate(query, dsInfo, traceLogsExploreQuery, "TimeGenerated")
	if err != nil {
		return "", &traceQueries, fmt.Errorf("failed to create traces logs explore query: %s", err)
	}
	traceQueries.TraceLogsExploreQuery = traceLogsExploreQuery

	return queryString, &traceQueries, nil
}

func buildAppInsightsQuery(ctx context.Context, query backend.DataQuery, dsInfo types.DatasourceInfo, appInsightsRegExp *regexp.Regexp, logger log.Logger) (*AzureLogAnalyticsQuery, error) {
	dashboardTime := true
	timeColumn := ""
	queryJSONModel := types.TracesJSONQuery{}
	err := json.Unmarshal(query.JSON, &queryJSONModel)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the Azure Traces query object from JSON: %w", err)
	}

	azureTracesTarget := queryJSONModel.AzureTraces

	resultFormat := ParseResultFormat(azureTracesTarget.ResultFormat, dataquery.AzureQueryTypeAzureTraces)

	resources := azureTracesTarget.Resources
	if query.QueryType == string(dataquery.AzureQueryTypeTraceExemplar) {
		subscription, err := utils.GetFirstSubscriptionOrDefault(ctx, dsInfo, logger)
		if err != nil {
			errorMessage := fmt.Errorf("failed to retrieve subscription for trace exemplars query: %w", err)
			return nil, utils.ApplySourceFromError(errorMessage, err)
		}
		resources = []string{fmt.Sprintf("/subscriptions/%s", subscription)}
	}

	if len(resources) == 0 {
		return nil, fmt.Errorf("no resources specified for Azure traces query")
	}

	resourceOrWorkspace := resources[0]
	appInsightsQuery := appInsightsRegExp.Match([]byte(resourceOrWorkspace))
	resourcesMap := make(map[string]bool, 0)
	if len(resources) > 1 {
		for _, resource := range resources {
			resourcesMap[strings.ToLower(resource)] = true
		}
		// Remove the base resource as that's where the query is run anyway
		delete(resourcesMap, strings.ToLower(resourceOrWorkspace))
	}

	operationId := ""
	if queryJSONModel.AzureTraces.OperationId != nil && *queryJSONModel.AzureTraces.OperationId != "" {
		operationId = *queryJSONModel.AzureTraces.OperationId
		resourcesMap, err = getCorrelationWorkspaces(ctx, resourceOrWorkspace, resourcesMap, dsInfo, operationId)
		if err != nil {
			errorMessage := fmt.Errorf("failed to retrieve correlation resources for operation ID - %s: %s", operationId, err)
			return nil, utils.ApplySourceFromError(errorMessage, err)
		}
	}

	queryResources := make([]string, 0)
	for resource := range resourcesMap {
		queryResources = append(queryResources, resource)
	}
	sort.Strings(queryResources)

	if query.QueryType == string(dataquery.AzureQueryTypeTraceExemplar) {
		resources = queryResources
		if len(resources) == 0 {
			return nil, fmt.Errorf("no correlation resources found for trace exemplar query with operation ID: %s", operationId)
		}
		resourceOrWorkspace = resources[0]
	}

	queryString, traceQueries, err := buildTraceQueries(query, dsInfo, queryJSONModel.AzureTraces, operationId, resultFormat, queryResources)
	if err != nil {
		return nil, err
	}

	apiURL := getApiURL(resourceOrWorkspace, appInsightsQuery, false)

	rawQuery, err := macros.KqlInterpolate(query, dsInfo, queryString, "TimeGenerated")
	if err != nil {
		return nil, err
	}

	timeColumn = "timestamp"

	return &AzureLogAnalyticsQuery{
		RefID:                   query.RefID,
		ResultFormat:            resultFormat,
		URL:                     apiURL,
		JSON:                    query.JSON,
		TimeRange:               query.TimeRange,
		Query:                   rawQuery,
		Resources:               resources,
		QueryType:               dataquery.AzureQueryType(query.QueryType),
		TraceExploreQuery:       traceQueries.TraceExploreQuery,
		TraceParentExploreQuery: traceQueries.TraceParentExploreQuery,
		TraceLogsExploreQuery:   traceQueries.TraceLogsExploreQuery,
		AppInsightsQuery:        appInsightsQuery,
		DashboardTime:           dashboardTime,
		TimeColumn:              timeColumn,
	}, nil
}
