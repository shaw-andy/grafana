package serviceaccounts

import (
	"fmt"
	"math"
	"strings"
)

const secondsPerDay = int64(24 * 60 * 60)

// ExceedsTokenExpirationDayLimit reports whether a token lifetime is longer than
// service_accounts.token_expiration_day_limit. The limit is a duration, not a
// calendar date: the stored expiry is the creation instant plus secondsToLive,
// so the lifetime must be compared to dayLimit*24h exactly. A dayLimit <= 0
// disables the limit.
func ExceedsTokenExpirationDayLimit(secondsToLive int64, dayLimit int64) bool {
	if dayLimit <= 0 || dayLimit > math.MaxInt64/secondsPerDay {
		return false
	}
	return secondsToLive > dayLimit*secondsPerDay
}

// generateLogin makes a generated string to have a ID for the service account across orgs and it's name
// this causes you to create a service account with the same name in different orgs
// not the same name in the same org
// -- WARNING:
// -- if you change this function you need to change the ExtSvcLoginPrefix as well
// -- to make sure they are not considered as regular service accounts
func GenerateLogin(prefix string, orgId int64, name string) string {
	generatedLogin := fmt.Sprintf("%v-%v-%v", prefix, orgId, strings.ToLower(name))
	// in case the name has multiple spaces or dashes in the prefix or otherwise, replace them with a single dash
	generatedLogin = strings.Replace(generatedLogin, "--", "-", 1)
	return strings.ReplaceAll(generatedLogin, " ", "-")
}

func ExtSvcLoginPrefix(orgID int64) string {
	return fmt.Sprintf("%s%d-%s", ServiceAccountPrefix, orgID, ExtSvcPrefix)
}

func IsExternalServiceAccount(login string) bool {
	parts := strings.SplitAfter(login, "-")
	if len(parts) < 4 {
		return false
	}

	return parts[0] == ServiceAccountPrefix && parts[2] == ExtSvcPrefix
}
