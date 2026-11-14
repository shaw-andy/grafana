package annotation

import (
	"context"
	"errors"
	"time"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
)

var (
	// ErrNotFound is returned when the requested annotation does not exist.
	ErrNotFound = errors.New("annotation not found")
	// ErrAlreadyExists is returned when a unique constraint would be violated.
	ErrAlreadyExists = errors.New("annotation already exists")
	// ErrInvalidInput is returned for caller-supplied input the backend cannot accept.
	ErrInvalidInput = errors.New("invalid annotation input")
)

type Store interface {
	Get(ctx context.Context, namespace, name string) (*annotationV0.Annotation, error)
	List(ctx context.Context, namespace string, opts ListOptions) (*AnnotationList, error)
	Create(ctx context.Context, annotation *annotationV0.Annotation) (*annotationV0.Annotation, error)
	Update(ctx context.Context, annotation *annotationV0.Annotation) (*annotationV0.Annotation, error)
	Delete(ctx context.Context, namespace, name string) error
	Close() error
}

type ListOptions struct {
	DashboardUID string
	PanelID      int64
	From         int64
	To           int64
	Limit        int64
	Continue     string
	// CreatedBy filters by the uid of the user who created the annotation
	CreatedBy      string
	Tags           []string
	TagsMatchAny   bool
	Scopes         []string
	ScopesMatchAny bool

	// LegacyID filters by the legacy numeric ID
	LegacyID int64

	// Deleted controls whether soft-deleted annotations (tombstones) are returned.
	Deleted DeletedFilter
}

// DeletedFilter controls whether soft-deleted annotations (tombstones) are
// included in a list.
type DeletedFilter int

const (
	DeletedExclude DeletedFilter = iota // live only (zero value)
	DeletedInclude                      // live and tombstones
	DeletedOnly                         // tombstones only
)

type AnnotationList struct {
	Items    []annotationV0.Annotation
	Continue string
}

type LifecycleManager interface {
	Cleanup(ctx context.Context, before time.Time) (int64, error)
}

// TagProvider counts tags over the annotations the requester in ctx is allowed to read.
type TagProvider interface {
	ListTags(ctx context.Context, namespace string, opts TagListOptions) ([]Tag, error)
}

// DashboardTagCounter counts tags per dashboard without checking access. Its counts must
// only be exposed after dropping the dashboards the requester cannot read.
type DashboardTagCounter interface {
	// ListDashboardTags returns at most opts.Limit rows, or every row when opts.Limit is 0.
	ListDashboardTags(ctx context.Context, namespace string, opts TagListOptions) ([]DashboardTag, error)
}

type TagListOptions struct {
	Prefix   string
	Contains string
	Limit    int
}

type Tag struct {
	Name  string
	Count int64
}

type DashboardTag struct {
	// DashboardUID is empty for organization annotations.
	DashboardUID string
	Name         string
	Count        int64
}
