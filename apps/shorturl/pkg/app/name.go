package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"

	shorturlv1beta1 "github.com/grafana/grafana/apps/shorturl/pkg/apis/shorturl/v1beta1"
)

// NewName returns a server-chosen short URL name. Anyone in the org who knows a
// name can read the stored path, so the name is the secret: rand.Text carries
// at least 128 bits from crypto/rand. Lowercasing keeps it a valid Kubernetes
// name and legacy UID, and the "s" prefix keeps the first character a letter.
func NewName() string {
	return "s" + strings.ToLower(rand.Text())
}

// mutateShortURL replaces any caller-supplied name or generateName on create,
// so every stored short URL has a name from NewName.
func mutateShortURL(_ context.Context, req *app.AdmissionRequest) (*app.MutatingResponse, error) {
	shortURL, ok := req.Object.(*shorturlv1beta1.ShortURL)
	if !ok {
		return nil, fmt.Errorf("expected ShortURL object, got %T", req.Object)
	}
	if req.Action == resource.AdmissionActionCreate {
		shortURL.SetName(NewName())
		shortURL.SetGenerateName("")
	}
	return &app.MutatingResponse{UpdatedObject: shortURL}, nil
}
