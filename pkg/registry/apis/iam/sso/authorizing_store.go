package sso

import (
	"context"
	"errors"
	"fmt"

	authlib "github.com/grafana/authlib/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/grafana/grafana/pkg/apimachinery/utils"
	iamv0 "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
)

// authorizingStore checks the provider of every SSOSetting it reads or writes.
// The API authorizer cannot do this alone: a collection create carries no name,
// a list returns every provider, and an update body can name a provider other
// than the one in the request path.
type authorizingStore struct {
	ssoStorage
	access authlib.AccessClient
}

// NewAuthorizingStore wraps the SSOSetting store so each operation is limited to
// providers the caller holds settings permissions for.
func NewAuthorizingStore(storage rest.Storage, access authlib.AccessClient) (rest.Storage, error) {
	inner, ok := storage.(ssoStorage)
	if !ok {
		return nil, fmt.Errorf("sso storage does not implement the expected interface set")
	}
	if access == nil {
		return nil, errors.New("sso storage requires an access client")
	}
	return &authorizingStore{ssoStorage: inner, access: access}, nil
}

func (s *authorizingStore) allowed(ctx context.Context, verb, provider string) (bool, error) {
	if provider == "" {
		return false, nil
	}
	ident, ok := authlib.AuthInfoFrom(ctx)
	if !ok {
		return false, apierrors.NewUnauthorized("no identity found for request")
	}
	res, err := s.access.Check(ctx, ident, authlib.CheckRequest{
		Verb:      verb,
		Group:     resource.GroupResource().Group,
		Resource:  resource.GroupResource().Resource,
		Namespace: genericapirequest.NamespaceValue(ctx),
		Name:      provider,
	}, "")
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

func (s *authorizingStore) authorize(ctx context.Context, verb, provider string) error {
	ok, err := s.allowed(ctx, verb, provider)
	if err != nil {
		return err
	}
	if !ok {
		return apierrors.NewForbidden(resource.GroupResource(), provider,
			fmt.Errorf("requires settings permission for sso provider %q", provider))
	}
	return nil
}

func (s *authorizingStore) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	if err := s.authorize(ctx, utils.VerbGet, name); err != nil {
		return nil, err
	}
	return s.ssoStorage.Get(ctx, name, options)
}

func (s *authorizingStore) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	out, err := s.ssoStorage.List(ctx, options)
	if err != nil {
		return nil, err
	}
	list, ok := out.(*iamv0.SSOSettingList)
	if !ok {
		return nil, fmt.Errorf("expected ssosetting list, got %T", out)
	}
	items := make([]iamv0.SSOSetting, 0, len(list.Items))
	for _, item := range list.Items {
		ok, err := s.allowed(ctx, utils.VerbGet, item.Name)
		if err != nil {
			return nil, err
		}
		if ok {
			items = append(items, item)
		}
	}
	list.Items = items
	return list, nil
}

func (s *authorizingStore) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	setting, ok := obj.(*iamv0.SSOSetting)
	if !ok {
		return nil, errors.New("expected ssosetting on create")
	}
	provider := setting.Name
	if provider == "" {
		return nil, apierrors.NewBadRequest("ssosetting name must be the sso provider")
	}
	if err := s.authorize(ctx, utils.VerbCreate, provider); err != nil {
		return nil, err
	}
	return s.ssoStorage.Create(ctx, obj, bindCreateValidation(provider, createValidation), options)
}

func (s *authorizingStore) Update(
	ctx context.Context,
	name string,
	objInfo rest.UpdatedObjectInfo,
	createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc,
	forceAllowCreate bool,
	options *metav1.UpdateOptions,
) (runtime.Object, bool, error) {
	if err := s.authorize(ctx, utils.VerbUpdate, name); err != nil {
		return nil, false, err
	}
	return s.ssoStorage.Update(ctx, name, &boundUpdatedObjectInfo{UpdatedObjectInfo: objInfo, provider: name},
		bindCreateValidation(name, createValidation), updateValidation, forceAllowCreate, options)
}

func (s *authorizingStore) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	if err := s.authorize(ctx, utils.VerbDelete, name); err != nil {
		return nil, false, err
	}
	return s.ssoStorage.Delete(ctx, name, deleteValidation, options)
}

// bindCreateValidation refuses the write when the object no longer names the
// provider that was authorized. The inner stores run it right before they act.
func bindCreateValidation(provider string, next rest.ValidateObjectFunc) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		if next != nil {
			if err := next(ctx, obj); err != nil {
				return err
			}
		}
		return requireProvider(obj, provider)
	}
}

// boundUpdatedObjectInfo refuses an updated object that names a provider other
// than the authorized one, since the inner stores upsert by object name.
type boundUpdatedObjectInfo struct {
	rest.UpdatedObjectInfo
	provider string
}

func (i *boundUpdatedObjectInfo) UpdatedObject(ctx context.Context, oldObj runtime.Object) (runtime.Object, error) {
	obj, err := i.UpdatedObjectInfo.UpdatedObject(ctx, oldObj)
	if err != nil {
		return nil, err
	}
	if err := requireProvider(obj, i.provider); err != nil {
		return nil, err
	}
	return obj, nil
}

func requireProvider(obj runtime.Object, provider string) error {
	setting, ok := obj.(*iamv0.SSOSetting)
	if !ok {
		return fmt.Errorf("expected ssosetting, got %T", obj)
	}
	if setting.Name != provider {
		return apierrors.NewBadRequest(fmt.Sprintf("ssosetting name %q does not match the requested provider %q", setting.Name, provider))
	}
	return nil
}
