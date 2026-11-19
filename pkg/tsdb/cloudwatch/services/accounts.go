package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	oam "github.com/aws/aws-sdk-go-v2/service/oam"
	"github.com/aws/smithy-go"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models/resources"
)

var ErrAccessDeniedException = errors.New("access denied. please check your IAM policy")

const (
	// accountsPageLimit bounds how many ListSinks and ListAttachedLinks requests a
	// single lookup makes, so a service that keeps returning a next token cannot
	// hold the request open.
	accountsPageLimit = 20
	// accountsItemLimit bounds how many accounts, including the monitoring
	// account, a single lookup returns.
	accountsItemLimit = 1000
)

type AccountsService struct {
	models.OAMAPIProvider
}

var NewAccountsService = func(oamClient models.OAMAPIProvider) models.AccountsProvider {
	return &AccountsService{oamClient}
}

func (a *AccountsService) GetAccountsForCurrentUserOrRole(ctx context.Context) ([]resources.ResourceResponse[resources.Account], error) {
	var nextToken *string
	var sinkIdentifier, sinkName *string
	for range accountsPageLimit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := a.ListSinks(ctx, &oam.ListSinksInput{NextToken: nextToken})
		if err != nil {
			smithyErr := &smithy.GenericAPIError{}
			if errors.As(err, &smithyErr) && smithyErr.Code == "AccessDeniedException" {
				return nil, fmt.Errorf("%w: %s", ErrAccessDeniedException, smithyErr.Message)
			}
			return nil, fmt.Errorf("ListSinks error: %w", err)
		}

		// Only the first sink is used, so there is no reason to read further pages.
		if len(response.Items) > 0 {
			sinkIdentifier = response.Items[0].Arn
			sinkName = response.Items[0].Name
			break
		}

		if !hasNextPage(response.NextToken) {
			break
		}
		nextToken = response.NextToken
	}

	if sinkIdentifier == nil {
		return nil, nil
	}

	response := []resources.Account{{
		Id:                  getAccountId(*sinkIdentifier),
		Label:               *sinkName,
		Arn:                 *sinkIdentifier,
		IsMonitoringAccount: true,
	}}

	nextToken = nil
	for range accountsPageLimit {
		remaining := accountsItemLimit - len(response)
		if remaining <= 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		links, err := a.ListAttachedLinks(ctx, &oam.ListAttachedLinksInput{
			SinkIdentifier: sinkIdentifier,
			NextToken:      nextToken,
			MaxResults:     aws.Int32(int32(remaining)),
		})
		if err != nil {
			return nil, fmt.Errorf("ListAttachedLinks error: %w", err)
		}

		for _, link := range links.Items {
			if len(response) >= accountsItemLimit {
				break
			}
			arn := *link.LinkArn
			response = append(response, resources.Account{
				Id:                  getAccountId(arn),
				Label:               *link.Label,
				Arn:                 arn,
				IsMonitoringAccount: false,
			})
		}

		if !hasNextPage(links.NextToken) {
			break
		}
		nextToken = links.NextToken
	}

	return valuesToListMetricResponse(response), nil
}

func hasNextPage(nextToken *string) bool {
	return nextToken != nil && *nextToken != ""
}
