package resources

import "net/url"

type DataSourcesRequest struct {
	Region    string
	Pattern   *string
	NextToken *string
}

func ParseDataSourcesRequest(parameters url.Values) (DataSourcesRequest, error) {
	return DataSourcesRequest{
		Region:    parameters.Get("region"),
		Pattern:   setIfNotEmptyString(parameters.Get("pattern")),
		NextToken: setIfNotEmptyString(parameters.Get("nextToken")),
	}, nil
}
