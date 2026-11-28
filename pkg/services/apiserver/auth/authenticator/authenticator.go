package authenticator

import (
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/klog/v2"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

// SystemGroupPrefix is the group prefix Kubernetes reserves for itself.
// Membership in system:masters, for example, passes every authorizer.
const SystemGroupPrefix = "system:"

// IsSystemGroup reports whether group uses the prefix Kubernetes reserves.
func IsSystemGroup(group string) bool {
	return strings.HasPrefix(group, SystemGroupPrefix)
}

// WithoutSystemGroups returns the groups that do not use the reserved prefix,
// in a new slice. A nil input stays nil.
func WithoutSystemGroups(groups []string) []string {
	if groups == nil {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if !IsSystemGroup(g) {
			out = append(out, g)
		}
	}
	return out
}

func NewAuthenticator(authRequestHandlers ...authenticator.Request) authenticator.Request {
	handlers := append([]authenticator.Request{authenticator.RequestFunc(identityAuthenticator)}, authRequestHandlers...)
	return union.New(handlers...)
}

var _ authenticator.RequestFunc = identityAuthenticator

// identityAuthenticator check if we have any identity set in context.
// If not we delegate authentication to next authenticator in the chain.
func identityAuthenticator(req *http.Request) (*authenticator.Response, bool, error) {
	ident, err := identity.GetRequester(req.Context())
	if err != nil {
		klog.V(5).Info("no idenitty in context", "err", err)
		return nil, false, nil
	}

	return &authenticator.Response{User: newKubernetesUser(ident)}, true, nil
}

// kubernetesUser is the view of a Grafana requester that Kubernetes sees.
// Grafana groups are team UIDs or identity provider group names, both of which
// users can influence, so they must never carry a Kubernetes system group.
// The groups are filtered once, here, so later changes to the requester cannot
// add one back.
type kubernetesUser struct {
	identity.Requester
	groups []string
}

func newKubernetesUser(r identity.Requester) *kubernetesUser {
	return &kubernetesUser{Requester: r, groups: WithoutSystemGroups(r.GetGroups())}
}

func (u *kubernetesUser) GetGroups() []string {
	return u.groups
}
