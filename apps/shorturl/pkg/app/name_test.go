package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"

	shorturlv1beta1 "github.com/grafana/grafana/apps/shorturl/pkg/apis/shorturl/v1beta1"
)

func TestNewName(t *testing.T) {
	seen := map[string]struct{}{}
	for range 100 {
		name := NewName()
		// "s" plus 26 base32 characters, 130 bits.
		require.Len(t, name, 27)
		require.Empty(t, validation.IsDNS1123Label(name), name)
		require.NotContains(t, seen, name)
		seen[name] = struct{}{}
	}
}

func TestMutateShortURL(t *testing.T) {
	newShortURL := func() *shorturlv1beta1.ShortURL {
		return &shorturlv1beta1.ShortURL{
			ObjectMeta: metav1.ObjectMeta{Name: "picked", GenerateName: "prefix"},
			Spec:       shorturlv1beta1.ShortURLSpec{Path: "d/abc"},
		}
	}

	t.Run("create replaces the caller name and generateName", func(t *testing.T) {
		res, err := mutateShortURL(context.Background(), &app.AdmissionRequest{
			Action: resource.AdmissionActionCreate,
			Object: newShortURL(),
		})
		require.NoError(t, err)
		got := res.UpdatedObject.(*shorturlv1beta1.ShortURL)
		assert.NotEqual(t, "picked", got.GetName())
		assert.Len(t, got.GetName(), 27)
		assert.Empty(t, got.GetGenerateName())
		assert.Equal(t, "d/abc", got.Spec.Path)
	})

	t.Run("update keeps the existing name", func(t *testing.T) {
		res, err := mutateShortURL(context.Background(), &app.AdmissionRequest{
			Action: resource.AdmissionActionUpdate,
			Object: newShortURL(),
		})
		require.NoError(t, err)
		assert.Equal(t, "picked", res.UpdatedObject.GetName())
	})

	t.Run("rejects other kinds", func(t *testing.T) {
		_, err := mutateShortURL(context.Background(), &app.AdmissionRequest{
			Action: resource.AdmissionActionCreate,
			Object: &resource.UntypedObject{},
		})
		require.Error(t, err)
	})
}
