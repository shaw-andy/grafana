package webhooks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kube-openapi/pkg/spec3"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/cmd/grafana-cli/logger"
	provisioningapis "github.com/grafana/grafana/pkg/registry/apis/provisioning"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/webhooks/pullrequest"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// renderCore is the subset of the provisioning APIBuilder the render connector depends on.
type renderCore interface {
	GetGroupVersion() schema.GroupVersion
	GetRepository(ctx context.Context, name string) (repository.Repository, error)
}

type renderConnector struct {
	unified resource.ResourceClient
	core    renderCore
}

func NewRenderConnector(unified resource.ResourceClient, core renderCore) *renderConnector {
	return &renderConnector{
		unified: unified,
		core:    core,
	}
}

func (*renderConnector) New() runtime.Object {
	return &provisioning.Repository{}
}

func (*renderConnector) Destroy() {}

func (*renderConnector) ProducesMIMETypes(verb string) []string {
	return []string{"application/json"}
}

func (c *renderConnector) ProducesObject(verb string) any {
	return c.New()
}

func (*renderConnector) ConnectMethods() []string {
	return []string{http.MethodGet}
}

func (*renderConnector) NewConnectOptions() (runtime.Object, bool, string) {
	return nil, true, ""
}

func (c *renderConnector) Authorize(_ context.Context, a authorizer.Attributes) (decision authorizer.Decision, reason string, err error) {
	if a.GetResource() == provisioning.RepositoryResourceInfo.GetName() && a.GetSubresource() == "render" {
		// The git provider fetches preview images without a Grafana identity, so the
		// request is authorized by the signed URL, which Connect verifies before
		// reading anything.
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionNoOpinion, "", nil
}

func (c *renderConnector) PostProcessOpenAPI(oas *spec3.OpenAPI) error {
	root := "/apis/" + c.core.GetGroupVersion().String() + "/"
	repoprefix := root + "namespaces/{namespace}/repositories/{name}"

	delete(oas.Paths.Paths, repoprefix+"/render")
	sub := oas.Paths.Paths[repoprefix+"/render/{path}"]
	if sub != nil {
		sub.Get.Description = "get a rendered preview image"
		sub.Get.Responses = &spec3.Responses{
			ResponsesProps: spec3.ResponsesProps{
				StatusCodeResponses: map[int]*spec3.Response{
					200: {
						ResponseProps: spec3.ResponseProps{
							Content: map[string]*spec3.MediaType{
								"image/png": {},
							},
							Description: "OK",
						},
					},
				},
			},
		}

		// Replace {path} with {guid} (it is a GUID, but all k8s sub-resources are called path)
		for _, v := range sub.Parameters {
			if v.Name == "path" {
				v.Name = "guid"
				v.Description = "Image GUID"
				break
			}
		}

		delete(oas.Paths.Paths, repoprefix+"/render/{path}")
		oas.Paths.Paths[repoprefix+"/render/{guid}"] = sub
	}

	return nil
}

func (c *renderConnector) UpdateStorage(storage map[string]rest.Storage) error {
	storage[provisioning.RepositoryResourceInfo.StoragePath("render")] = provisioningapis.WithTimeout(c, 20*time.Second)
	return nil
}

func (c *renderConnector) Connect(
	ctx context.Context,
	name string,
	opts runtime.Object,
	responder rest.Responder,
) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namespace := request.NamespaceValue(ctx)
		prefix := fmt.Sprintf("/%s/render", name)
		idx := strings.Index(r.URL.Path, prefix)
		if idx == -1 {
			logger.Debug("failed to find a file path in the URL")
			responder.Error(apierrors.NewBadRequest("invalid request path"))
			return
		}
		blobID := strings.TrimPrefix(r.URL.Path[idx+len(prefix):], "/")
		if len(blobID) == 0 {
			responder.Error(apierrors.NewNotFound(provisioning.RepositoryResourceInfo.GroupResource(), "render"))
			return
		}
		if !provisioningapis.ValidUUID(blobID) {
			responder.Error(apierrors.NewBadRequest(fmt.Sprintf("invalid blob id: %s", blobID)))
			return
		}

		if err := c.verifySignature(ctx, r, namespace, name, blobID); err != nil {
			logger.Debug("rejected preview image request", "namespace", namespace, "repository", name, "err", err)
			responder.Error(apierrors.NewForbidden(provisioning.RepositoryResourceInfo.GroupResource(), name, errors.New("invalid or expired preview signature")))
			return
		}

		rsp, err := c.unified.GetBlob(ctx, &resourcepb.GetBlobRequest{
			Resource: &resourcepb.ResourceKey{
				Namespace: namespace,
				Group:     provisioning.GROUP,
				Resource:  provisioning.RepositoryResourceInfo.GroupResource().Resource,
				Name:      name,
			},
			MustProxyBytes: true,
			Uid:            blobID,
		})
		if err != nil {
			responder.Error(err)
			return
		}
		if rsp.Error != nil {
			responder.Error(resource.GetError(rsp.Error))
			return
		}

		if len(rsp.Value) > 0 {
			if rsp.ContentType != "" {
				w.Header().Add("Content-Type", rsp.ContentType)
			}
			_, err = w.Write(rsp.Value)
			if err != nil {
				responder.Error(err)
				return
			}
		} else {
			responder.Error(&apierrors.StatusError{
				ErrStatus: v1.Status{
					Code:    http.StatusNoContent,
					Message: "empty body",
				},
			})
		}
	}), nil
}

// verifySignature checks that the request carries an unexpired signature that
// the repository's key issued for exactly this namespace, repository, and blob.
func (c *renderConnector) verifySignature(ctx context.Context, r *http.Request, namespace, name, blobID string) error {
	// Parse and time-check first so unsigned or stale requests never load the repository.
	sig, err := pullrequest.ParsePreviewSignature(r.URL.Query(), time.Now())
	if err != nil {
		return err
	}

	repoCtx, _, err := identity.WithProvisioningIdentity(ctx, namespace)
	if err != nil {
		return err
	}
	repo, err := c.core.GetRepository(repoCtx, name)
	if err != nil {
		return err
	}
	signer, ok := repo.(repository.PreviewSigningRepository)
	if !ok {
		return errors.New("repository cannot sign preview URLs")
	}
	key, err := signer.PreviewSigningKey()
	if err != nil {
		return err
	}
	if !sig.Verify(key, namespace, name, blobID) {
		return pullrequest.ErrPreviewSignatureInvalid
	}
	return nil
}

var (
	_ rest.Connecter       = (*renderConnector)(nil)
	_ rest.Storage         = (*renderConnector)(nil)
	_ rest.StorageMetadata = (*renderConnector)(nil)
)
