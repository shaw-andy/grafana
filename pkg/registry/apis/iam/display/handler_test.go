package display

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	iam "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
)

func displayRequest(t *testing.T, auth authlib.AuthInfo, keys ...string) *http.Request {
	t.Helper()
	path := "/apis/iam.grafana.app/v0alpha1/namespaces/default/display?"
	for i, k := range keys {
		if i > 0 {
			path += "&"
		}
		path += "key=" + k
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != nil {
		req = req.WithContext(authlib.WithAuthInfo(req.Context(), auth))
	}
	return req
}

func TestDisplayHandler_handleDisplay(t *testing.T) {
	caller := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserUID:   "u1",
		UserID:    1,
		OrgID:     1,
		Namespace: "default",
	}
	self := iam.Display{Identity: iam.IdentityRef{Type: authlib.TypeUser, Name: "u1"}, DisplayName: "Caller", InternalID: 1}
	other := iam.Display{Identity: iam.IdentityRef{Type: authlib.TypeUser, Name: "u2"}, DisplayName: "Other", InternalID: 2}
	sa := iam.Display{Identity: iam.IdentityRef{Type: authlib.TypeServiceAccount, Name: "sa3"}, DisplayName: "SA", InternalID: 3}
	anonymous := iam.Display{Identity: iam.IdentityRef{Type: authlib.TypeAnonymous}, DisplayName: "Anonymous"}

	newResolver := func() *fakeResolver {
		return &fakeResolver{result: &iam.DisplayList{Items: []iam.Display{self, other, sa}}}
	}

	decode := func(t *testing.T, rec *httptest.ResponseRecorder) iam.DisplayList {
		t.Helper()
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var got iam.DisplayList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		return got
	}

	t.Run("without an access policy only the caller is resolved", func(t *testing.T) {
		h := NewDisplayHandler(nil, newResolver())
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u1", "u2", "sa3"))
		require.Equal(t, []iam.Display{self}, decode(t, rec).Items)
	})

	t.Run("access policy decides which other identities are resolved", func(t *testing.T) {
		var gotNS authlib.NamespaceInfo
		policy := func(_ context.Context, ns authlib.NamespaceInfo) (MemberFilter, error) {
			gotNS = ns
			return func(m Member) bool { return m.Type == authlib.TypeServiceAccount }, nil
		}
		h := NewDisplayHandler(policy, newResolver())
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u1", "u2", "sa3"))
		require.Equal(t, []iam.Display{self, sa}, decode(t, rec).Items)
		require.Equal(t, "default", gotNS.Value)
	})

	t.Run("a nil filter from the policy resolves only the caller", func(t *testing.T) {
		policy := func(context.Context, authlib.NamespaceInfo) (MemberFilter, error) { return nil, nil }
		h := NewDisplayHandler(policy, newResolver())
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u1", "u2"))
		require.Equal(t, []iam.Display{self}, decode(t, rec).Items)
	})

	t.Run("caller self match requires the same identity type", func(t *testing.T) {
		impostor := iam.Display{Identity: iam.IdentityRef{Type: authlib.TypeServiceAccount, Name: "u1"}, DisplayName: "Impostor"}
		h := NewDisplayHandler(nil, &fakeResolver{result: &iam.DisplayList{Items: []iam.Display{impostor}}})
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u1"))
		require.Empty(t, decode(t, rec).Items)
	})

	t.Run("policy error returns 500 without resolving", func(t *testing.T) {
		resolver := newResolver()
		policy := func(context.Context, authlib.NamespaceInfo) (MemberFilter, error) { return nil, errors.New("boom") }
		h := NewDisplayHandler(policy, resolver)
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u2"))
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Nil(t, resolver.gotKeys)
	})

	t.Run("terminal identities are still returned", func(t *testing.T) {
		resolver := &fakeResolver{result: &iam.DisplayList{Items: []iam.Display{other}}}
		h := NewDisplayHandler(nil, &constResolver{inner: resolver, constants: []iam.Display{anonymous}})
		rec := httptest.NewRecorder()
		h.handleDisplay(rec, displayRequest(t, caller, "u2", "anonymous:"))
		require.Equal(t, []iam.Display{anonymous}, decode(t, rec).Items)
	})
}

// constResolver appends terminal entries after the filtered inner result, the
// same way the real resolvers append parsed constant keys.
type constResolver struct {
	inner     *fakeResolver
	constants []iam.Display
}

func (c *constResolver) GetDisplayList(ctx context.Context, ns authlib.NamespaceInfo, keys []string, allow MemberFilter) (*iam.DisplayList, error) {
	rsp, err := c.inner.GetDisplayList(ctx, ns, keys, allow)
	if err != nil {
		return nil, err
	}
	if rsp == nil {
		rsp = &iam.DisplayList{}
	}
	rsp.Items = append(rsp.Items, c.constants...)
	return rsp, nil
}
