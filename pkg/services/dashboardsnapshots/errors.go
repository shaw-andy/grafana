package dashboardsnapshots

import (
	"github.com/grafana/grafana/pkg/apimachinery/errutil"
)

var ErrBaseNotFound = errutil.NotFound("dashboardsnapshots.not-found", errutil.WithPublicMessage("Snapshot not found"))

var ErrDashboardSnapshotAlreadyExists = errutil.Conflict("dashboardsnapshots.keyAlreadyExists", errutil.WithPublicMessage("Snapshot key already exists"))

var ErrInvalidSnapshotKey = errutil.BadRequest("dashboardsnapshots.invalidKey",
	errutil.WithPublicMessage("Snapshot keys may only contain letters, digits, '-' and '_'."),
)

var ErrExternalSnapshotInvalidKey = errutil.BadGateway("dashboardsnapshots.externalInvalidKey",
	errutil.WithPublicMessage("External snapshot server returned an invalid snapshot key."),
)
