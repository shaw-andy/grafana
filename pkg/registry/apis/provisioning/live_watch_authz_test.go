package provisioning

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	clientrest "k8s.io/client-go/rest"
	basecompatibility "k8s.io/component-base/compatibility"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioningv0 "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	commonv0 "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/apiserver/endpoints/responsewriter"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/apiserver/auth/authenticator"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/apiserver/options"
	"github.com/grafana/grafana/pkg/services/live/features"
	"github.com/grafana/grafana/pkg/services/live/model"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	connectionURLMarker       = "https://git.example.test/private/repo"
	connectionAppIDMarker     = "github-app-id-marker"
	connectionInstallMarker   = "github-installation-id-marker"
	connectionClientIDMarker  = "oauth-client-id-marker"
	connectionSecretRefMarker = "secret-ref-name-marker"
	jobPullRequestURLMarker   = "https://git.example.test/private/repo/pull/7"
	historicJobURLMarker      = "https://git.example.test/private/repo/pull/8"
)

// denyAccess is the access-checker result used when a caller has no explicit
// permission. Role fallback then decides, which is how connections and historic
// jobs stay admin-only and jobs stay editor-only.
type denyAccess struct{}

func (denyAccess) Check(context.Context, authlib.AuthInfo, authlib.CheckRequest, string) (authlib.CheckResponse, error) {
	return authlib.CheckResponse{Allowed: false}, nil
}

// replayStorage serves one object to every watch. The real registry store does
// the same for resourceVersion 0: it replays the current object. This storage
// does not authorize; the handler chain in front of it does.
type replayStorage struct {
	rest.TableConvertor

	singular string
	newFn    func() runtime.Object
	newList  func() runtime.Object
	object   runtime.Object
	stop     <-chan struct{}

	mu       sync.Mutex
	versions []string
}

func newReplayStorage(info utils.ResourceInfo, object runtime.Object, stop <-chan struct{}) *replayStorage {
	return &replayStorage{
		TableConvertor: info.TableConverter(),
		singular:       info.GetSingularName(),
		newFn:          info.NewFunc,
		newList:        info.NewListFunc,
		object:         object,
		stop:           stop,
	}
}

func (s *replayStorage) New() runtime.Object     { return s.newFn() }
func (s *replayStorage) Destroy()                {}
func (s *replayStorage) NamespaceScoped() bool   { return true }
func (s *replayStorage) GetSingularName() string { return s.singular }
func (s *replayStorage) NewList() runtime.Object { return s.newList() }

func (s *replayStorage) List(context.Context, *metainternalversion.ListOptions) (runtime.Object, error) {
	return s.newList(), nil
}

func (s *replayStorage) Watch(_ context.Context, options *metainternalversion.ListOptions) (watch.Interface, error) {
	rv := ""
	if options != nil {
		rv = options.ResourceVersion
	}
	s.mu.Lock()
	s.versions = append(s.versions, rv)
	s.mu.Unlock()

	fw := watch.NewFake()
	obj := s.object.DeepCopyObject()
	go func() {
		fw.Add(obj)
		<-s.stop
		fw.Stop()
	}()
	return fw, nil
}

func (s *replayStorage) resourceVersions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.versions))
	copy(out, s.versions)
	return out
}

func (s *replayStorage) resetVersions() {
	s.mu.Lock()
	s.versions = nil
	s.mu.Unlock()
}

type loopbackConfigProvider struct {
	cfg *clientrest.Config
}

func (p loopbackConfigProvider) GetRestConfig(context.Context) (*clientrest.Config, error) {
	return p.cfg, nil
}

var _ apiserver.RestConfigProvider = loopbackConfigProvider{}

func TestLiveWatchLoopbackReadsProvisioningObjects(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

	connection := &provisioningv0.Connection{
		TypeMeta: metav1.TypeMeta{APIVersion: provisioningv0.APIVERSION, Kind: "Connection"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "github",
			Namespace: "default",
		},
		Spec: provisioningv0.ConnectionSpec{
			Title: "private",
			Type:  provisioningv0.GithubConnectionType,
			URL:   connectionURLMarker,
			GitHub: &provisioningv0.GitHubConnectionConfig{
				AppID:          connectionAppIDMarker,
				InstallationID: connectionInstallMarker,
			},
			OAuth: &provisioningv0.ConnectionOAuthConfig{ClientID: connectionClientIDMarker},
		},
		Secure: provisioningv0.ConnectionSecure{
			PrivateKey: commonv0.InlineSecureValue{Name: connectionSecretRefMarker},
		},
	}
	job := &provisioningv0.Job{
		TypeMeta: metav1.TypeMeta{APIVersion: provisioningv0.APIVERSION, Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "job-1",
			Namespace: "default",
		},
		Spec: provisioningv0.JobSpec{
			Action: provisioningv0.JobActionPullRequest,
			PullRequest: &provisioningv0.PullRequestJobOptions{
				URL: jobPullRequestURLMarker,
			},
		},
	}
	historic := &provisioningv0.HistoricJob{
		TypeMeta: metav1.TypeMeta{APIVersion: provisioningv0.APIVERSION, Kind: "HistoricJob"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "historic-1",
			Namespace: "default",
		},
		Spec: provisioningv0.JobSpec{
			Action: provisioningv0.JobActionPullRequest,
			PullRequest: &provisioningv0.PullRequestJobOptions{
				URL: historicJobURLMarker,
			},
		},
	}

	connections := newReplayStorage(provisioningv0.ConnectionResourceInfo, connection, stop)
	jobs := newReplayStorage(provisioningv0.JobResourceInfo, job, stop)
	historicJobs := newReplayStorage(provisioningv0.HistoricJobResourceInfo, historic, stop)

	session := auth.NewSessionAccessChecker(denyAccess{})
	api := &APIBuilder{
		gv:                 provisioningv0.SchemeGroupVersion,
		isPreferredVersion: true,
		accessWithAdmin:    session.WithFallbackRole(identity.RoleAdmin),
		accessWithEditor:   session.WithFallbackRole(identity.RoleEditor),
		accessWithViewer:   session.WithFallbackRole(identity.RoleViewer),
	}
	provAuth := api.GetAuthorizer()

	runtimeScheme := builder.ProvideScheme()
	require.NoError(t, api.InstallSchema(runtimeScheme))
	codecs := builder.ProvideCodecFactory(runtimeScheme)

	serverConfig := genericapiserver.NewRecommendedConfig(codecs)
	serverConfig.ExternalAddress = "192.0.2.10:443"
	serverConfig.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString("1.35", "", "")
	serverConfig.LoopbackClientConfig = &clientrest.Config{
		Host:        "https://127.0.0.1:6443",
		BearerToken: "test-loopback-token",
		QPS:         -1,
	}

	defs := builder.GetOpenAPIDefinitions([]builder.APIGroupBuilder{api})
	namer := openapi.NewDefinitionNamer(runtimeScheme, k8sscheme.Scheme)
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(defs, namer)
	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(defs, namer)

	authz := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	authz.Register(provisioningv0.SchemeGroupVersion, provAuth)
	serverConfig.Authorization.Authorizer = authz
	serverConfig.Authentication.Authenticator = authenticator.NewAuthenticator()
	serverConfig.BuildHandlerChainFunc = builder.GetDefaultBuildHandlerChainFunc(nil, prometheus.NewRegistry())

	server, err := serverConfig.Complete().New("grafana-apiserver", genericapiserver.NewEmptyDelegate())
	require.NoError(t, err)

	group := genericapiserver.NewDefaultAPIGroupInfo(provisioningv0.GROUP, runtimeScheme, metav1.ParameterCodec, codecs)
	group.VersionedResourcesStorageMap[provisioningv0.VERSION] = map[string]rest.Storage{
		provisioningv0.ConnectionResourceInfo.GetName():  connections,
		provisioningv0.JobResourceInfo.GetName():         jobs,
		provisioningv0.HistoricJobResourceInfo.GetName(): historicJobs,
	}
	require.NoError(t, server.InstallAPIGroup(&group))

	server.LoopbackClientConfig.Transport = &options.RoundTripperFunc{
		Fn: responsewriter.WrapHandler(server.Handler),
	}
	server.LoopbackClientConfig.TLSClientConfig = clientrest.TLSClientConfig{}

	var published []string
	var publishMu sync.Mutex
	runner := features.NewWatchRunner(func(ns, channel string, data []byte) error {
		publishMu.Lock()
		published = append(published, ns+" "+channel+" "+string(data))
		publishMu.Unlock()
		return nil
	}, loopbackConfigProvider{cfg: server.LoopbackClientConfig})

	dump := func() string {
		publishMu.Lock()
		defer publishMu.Unlock()
		return strings.Join(published, "\n")
	}
	clearPublished := func() {
		publishMu.Lock()
		published = nil
		publishMu.Unlock()
	}

	viewer := orgUser(11, "viewer-uid", identity.RoleViewer)
	editor := orgUser(12, "editor-uid", identity.RoleEditor)
	admin := orgUser(13, "admin-uid", identity.RoleAdmin)

	cases := []struct {
		name     string
		user     *user.SignedInUser
		resource string
		storage  *replayStorage
		marker   string
		allow    bool
	}{
		{name: "viewer connections", user: viewer, resource: provisioningv0.ConnectionResourceInfo.GetName(), storage: connections, marker: connectionURLMarker, allow: false},
		{name: "editor connections", user: editor, resource: provisioningv0.ConnectionResourceInfo.GetName(), storage: connections, marker: connectionURLMarker, allow: false},
		{name: "admin connections", user: admin, resource: provisioningv0.ConnectionResourceInfo.GetName(), storage: connections, marker: connectionURLMarker, allow: true},
		{name: "viewer jobs", user: viewer, resource: provisioningv0.JobResourceInfo.GetName(), storage: jobs, marker: jobPullRequestURLMarker, allow: false},
		{name: "editor jobs", user: editor, resource: provisioningv0.JobResourceInfo.GetName(), storage: jobs, marker: jobPullRequestURLMarker, allow: true},
		{name: "admin jobs", user: admin, resource: provisioningv0.JobResourceInfo.GetName(), storage: jobs, marker: jobPullRequestURLMarker, allow: true},
		{name: "viewer historic jobs", user: viewer, resource: provisioningv0.HistoricJobResourceInfo.GetName(), storage: historicJobs, marker: historicJobURLMarker, allow: false},
		{name: "editor historic jobs", user: editor, resource: provisioningv0.HistoricJobResourceInfo.GetName(), storage: historicJobs, marker: historicJobURLMarker, allow: false},
		{name: "admin historic jobs", user: admin, resource: provisioningv0.HistoricJobResourceInfo.GetName(), storage: historicJobs, marker: historicJobURLMarker, allow: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, reason, authErr := provAuth.Authorize(identity.WithRequester(context.Background(), tc.user), authorizer.AttributesRecord{
				User:            tc.user,
				Verb:            "watch",
				APIGroup:        provisioningv0.GROUP,
				APIVersion:      provisioningv0.VERSION,
				Resource:        tc.resource,
				Namespace:       "default",
				ResourceRequest: true,
			})
			require.NoError(t, authErr)
			if tc.allow {
				require.Equal(t, authorizer.DecisionAllow, decision, reason)
			} else {
				require.Equal(t, authorizer.DecisionDeny, decision, reason)
			}

			clearPublished()
			tc.storage.resetVersions()

			path := provisioningv0.VERSION + "/" + tc.resource + "/" + tc.user.GetIdentifier()
			channel := "watch/" + provisioningv0.GROUP + "/" + path
			_, status, subErr := runner.OnSubscribe(context.Background(), tc.user, model.SubscribeEvent{
				Channel: channel,
				Path:    path,
				Data:    []byte(`{"resourceVersion":"0"}`),
			})

			if !tc.allow {
				if status == backend.SubscribeStreamStatusOK && subErr == nil {
					body := waitForMarker(dump, tc.marker, 3*time.Second)
					require.NotContainsf(t, body, tc.marker,
						"live watch published a %s object to %s", tc.resource, tc.user.GetOrgRole())
					require.Failf(t, "restricted watch was accepted",
						"live watch for %s accepted a %s watch the provisioning authorizer denies; published %q",
						tc.user.GetOrgRole(), tc.resource, body)
				}
				require.NotEqual(t, backend.SubscribeStreamStatusOK, status)
				require.Error(t, subErr)
				require.NotContains(t, dump(), tc.marker)
				return
			}

			require.NoError(t, subErr)
			require.Equal(t, backend.SubscribeStreamStatusOK, status)
			body := waitForMarker(dump, tc.marker, 5*time.Second)
			require.Contains(t, body, tc.marker)
			require.Contains(t, tc.storage.resourceVersions(), "0")
			if tc.resource == provisioningv0.ConnectionResourceInfo.GetName() {
				require.Contains(t, body, connectionAppIDMarker)
				require.Contains(t, body, connectionInstallMarker)
				require.Contains(t, body, connectionClientIDMarker)
				require.Contains(t, body, connectionSecretRefMarker)
			}
		})
	}
}

func waitForMarker(dump func() string, marker string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	body := dump()
	for !strings.Contains(body, marker) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		body = dump()
	}
	return body
}

func orgUser(id int64, uid string, role identity.RoleType) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:    id,
		UserUID:   uid,
		OrgID:     1,
		Namespace: "default",
		OrgRole:   role,
		Login:     uid,
		Name:      uid,
	}
}
