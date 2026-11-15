package userstorage

import (
	"context"
	"strings"
	"testing"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apis/userstorage/v0alpha1"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		requesterID string
		objectName  string
		data        map[string]string
		expectError bool
		// Update authorization already checks the name against the caller, so
		// ValidateUpdate only enforces service and size.
		expectUpdateError bool
	}{
		{
			name:        "valid userstorage object",
			requesterID: "123",
			objectName:  "basic-panel:123",
			expectError: false,
		},
		{
			name:        "valid built-in service",
			requesterID: "123",
			objectName:  "grafana-splash-screen:123",
			expectError: false,
		},
		{
			name:        "invalid userstorage object",
			requesterID: "123",
			objectName:  "basic-panel:456",
			expectError: true,
		},
		{
			name:              "unknown service",
			requesterID:       "123",
			objectName:        "not-installed:123",
			expectError:       true,
			expectUpdateError: true,
		},
		{
			name:              "object too large",
			requesterID:       "123",
			objectName:        "basic-panel:123",
			data:              map[string]string{"k": strings.Repeat("x", maxObjectSizeBytes)},
			expectError:       true,
			expectUpdateError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requester := &identity.StaticRequester{Type: "user", UserUID: tt.requesterID}
			obj := &v0alpha1.UserStorage{
				ObjectMeta: v1.ObjectMeta{
					Name: tt.objectName,
				},
				Spec: v0alpha1.UserStorageSpec{Data: tt.data},
			}
			ctx := identity.WithRequester(context.Background(), requester)

			strategy := newStrategy(nil, schema.GroupVersion{}, prometheus.DefaultRegisterer)
			strategy.pluginStore = pluginstore.NewFakePluginStore(pluginstore.Plugin{JSONData: plugins.JSONData{ID: "basic-panel"}})
			errs := strategy.Validate(ctx, obj)

			if tt.expectError {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}

			errs = strategy.ValidateUpdate(ctx, obj, obj.DeepCopy())
			if tt.expectUpdateError {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
