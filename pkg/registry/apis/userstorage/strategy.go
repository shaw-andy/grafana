package userstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
)

// maxObjectSizeBytes caps the JSON-encoded size of a single user storage object.
const maxObjectSizeBytes = 3 * 1024 * 1024

// builtInServices are the core Grafana services that store user data. Any other
// service name must be the ID of an installed plugin, so a user can hold at most
// one object per known service.
var builtInServices = map[string]struct{}{
	"grafana-splash-screen":   {},
	"grafana-runtime":         {},
	"grafana-help-flags":      {},
	"advisor-redirect-notice": {},
	"alerting":                {},
}

var (
	// Target for user storage size < 3MB
	userstorageSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "userstorage",
		Name:      "object_size_bytes",
		Help:      "Histogram of user storage object sizes in bytes, broken down by service name",
		Buckets:   prometheus.ExponentialBucketsRange(1024, 8*1024*1024, 8), // From 1 KB to 8 MB
	}, []string{"service"})
)

type genericStrategy interface {
	rest.RESTCreateStrategy
	rest.RESTUpdateStrategy
}

type userstorageStrategy struct {
	genericStrategy

	registerer prometheus.Registerer
	// pluginStore resolves plugin IDs used as service names. When nil, only
	// builtInServices are accepted.
	pluginStore pluginstore.Store
}

var once sync.Once

func newStrategy(typer runtime.ObjectTyper, gv schema.GroupVersion, registerer prometheus.Registerer) *userstorageStrategy {
	once.Do(func() {
		if registerer != nil {
			registerer.MustRegister(
				userstorageSize,
			)
		}
	})
	genericStrategy := grafanaregistry.NewStrategy(typer, gv)
	return &userstorageStrategy{genericStrategy: genericStrategy, registerer: registerer}
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

func (g *userstorageStrategy) isKnownService(ctx context.Context, service string) bool {
	if _, ok := builtInServices[service]; ok {
		return true
	}
	if g.pluginStore == nil {
		return false
	}
	_, ok := g.pluginStore.Plugin(ctx, service)
	return ok
}

// validateObject checks the service and size of obj and, when valid, records its
// size. The histogram is only fed allowlisted services so its label set stays bounded.
func (g *userstorageStrategy) validateObject(ctx context.Context, name string, obj runtime.Object) field.ErrorList {
	namePath := field.NewPath("metadata").Child("name")
	parsedName, err := parseName(name)
	if err != nil {
		return field.ErrorList{field.Invalid(namePath, name, err.Error())}
	}
	if !g.isKnownService(ctx, parsedName.Service) {
		return field.ErrorList{field.Forbidden(namePath, fmt.Sprintf("unknown service %q: service must be a built-in service or an installed plugin ID", parsedName.Service))}
	}

	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(obj); err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to encode object: %v", err))}
	}
	if b.Len() > maxObjectSizeBytes {
		return field.ErrorList{field.TooLong(field.NewPath("spec"), "", maxObjectSizeBytes)}
	}

	userstorageSize.WithLabelValues(parsedName.Service).Observe(float64(b.Len()))
	return nil
}

// Validate ensures that when creating a userstorage object, the name matches the user id,
// the service is known, and the object is within the size limit.
func (g *userstorageStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	u, err := identity.GetRequester(ctx)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to get requester: %v", err))}
	}

	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to get meta accessor: %v", err))}
	}

	nameMatch := compareResourceNameAndUserUID(meta.GetName(), u)
	if !nameMatch {
		return field.ErrorList{field.Forbidden(field.NewPath("metadata").Child("name"), "name must match service:user_uid")}
	}

	return g.validateObject(ctx, meta.GetName(), obj)
}

func (g *userstorageStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to get meta accessor: %v", err))}
	}

	return g.validateObject(ctx, meta.GetName(), obj)
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
