package logsdrilldown

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/grafana/grafana-app-sdk/app"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

// validateLogsDrilldownOwner ensures a LogsDrilldown is only stored under the requester's own name.
func validateLogsDrilldownOwner(ctx context.Context, req *app.AdmissionRequest) error {
	u, err := identity.GetRequester(ctx)
	if err != nil {
		return fmt.Errorf("valid user is required: %w", err)
	}

	if u.GetIsGrafanaAdmin() {
		return nil
	}

	if req.Object == nil {
		return errors.New("object is required")
	}

	if !compareResourceNameAndUserUID(req.Object.GetName(), u) {
		return errors.New("name must match service:user_uid")
	}

	return nil
}

func compareResourceNameAndUserUID(name string, u identity.Requester) bool {
	parsedName, err := parseName(name)
	if err != nil {
		return false
	}

	// u.GetUID() returns user:<user_uid> so we need to remove the user: prefix
	userUID := strings.Split(u.GetUID(), ":")
	if len(userUID) != 2 {
		return false
	}

	return parsedName.UID == userUID[1]
}

type storageObjectName struct {
	Service string
	UID     string
}

func parseName(name string) (*storageObjectName, error) {
	vals := strings.Split(name, ":")
	if len(vals) != 2 {
		return nil, errors.New("name must be in the format <service>:<user_uid>")
	}

	return &storageObjectName{
		Service: vals[0],
		UID:     vals[1],
	}, nil
}
