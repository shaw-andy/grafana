package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// mediaMarkup is annotation text a creator can store today. The path is a
// cookie-authenticated GET that changes the viewer's active organization.
const mediaMarkup = `deploy note <img src="/profile/switch-org/2" alt=""><audio src="/profile/switch-org/2"></audio><video poster="/profile/switch-org/2"></video>`

func TestAnnotationWritesDoNotStoreLoadableMedia(t *testing.T) {
	folderUID := "test-folder"
	createOrg := []accesscontrol.Permission{{
		Action: accesscontrol.ActionAnnotationsCreate,
		Scope:  accesscontrol.ScopeAnnotationsTypeOrganization,
	}}
	writeOrg := []accesscontrol.Permission{{
		Action: accesscontrol.ActionAnnotationsWrite,
		Scope:  accesscontrol.ScopeAnnotationsTypeOrganization,
	}}

	tests := []struct {
		desc        string
		method      string
		path        string
		body        string
		permissions []accesscontrol.Permission
		seed        *annotations.Item
	}{
		{
			desc:        "create",
			method:      http.MethodPost,
			path:        "/api/annotations",
			body:        `{"text":"` + jsonEscape(mediaMarkup) + `","time":1}`,
			permissions: createOrg,
		},
		{
			desc:        "graphite create",
			method:      http.MethodPost,
			path:        "/api/annotations/graphite",
			body:        `{"what":"` + jsonEscape(mediaMarkup) + `","when":1,"tags":[]}`,
			permissions: createOrg,
		},
		{
			desc:        "update",
			method:      http.MethodPut,
			path:        "/api/annotations/1",
			body:        `{"text":"` + jsonEscape(mediaMarkup) + `","time":1}`,
			permissions: writeOrg,
			seed:        &annotations.Item{ID: 1, Text: "old", DashboardID: 0},
		},
		{
			desc:        "patch",
			method:      http.MethodPatch,
			path:        "/api/annotations/1",
			body:        `{"text":"` + jsonEscape(mediaMarkup) + `"}`,
			permissions: writeOrg,
			seed:        &annotations.Item{ID: 1, Text: "old", DashboardID: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			repo := &recordingAnnotationsRepo{}
			if tt.seed != nil {
				require.NoError(t, repo.Save(context.Background(), tt.seed))
				repo.saved = nil
			}

			server := SetupAPITestServer(t, func(hs *HTTPServer) {
				hs.Cfg = setting.NewCfg()
				hs.annotationsRepo = repo
				hs.Features = featuremgmt.WithFeatures()
				dashService := &dashboards.FakeDashboardService{}
				folderService := &foldertest.FakeService{}
				folderService.ExpectedFolder = &folder.Folder{UID: folderUID, ID: 1}
				hs.DashboardService = dashService
				hs.folderService = folderService
				hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
				hs.AccessControl.RegisterScopeAttributeResolver(AnnotationTypeScopeResolver(hs.annotationsRepo, hs.Features, dashService, folderService))
				hs.AccessControl.RegisterScopeAttributeResolver(dashboards.NewDashboardUIDScopeResolver(dashService, folderService))
			})

			req := webtest.RequestWithSignedInUser(
				server.NewRequest(tt.method, tt.path, strings.NewReader(tt.body)),
				authedUserWithPermissions(1, 1, tt.permissions),
			)
			res, err := server.SendJSON(req)
			require.NoError(t, err)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			require.Equal(t, http.StatusOK, res.StatusCode, string(body))

			require.NotEmpty(t, repo.saved)
			for _, item := range repo.saved {
				require.Empty(t, mediaResourceURLs(item.Text), "stored text %q", item.Text)
			}
		})
	}
}

func jsonEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return replacer.Replace(value)
}

func mediaResourceURLs(markup string) []string {
	doc, err := html.Parse(strings.NewReader(markup))
	if err != nil {
		return []string{markup}
	}

	var urls []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "img", "audio", "video", "source", "track", "image":
				for _, attr := range n.Attr {
					switch attr.Key {
					case "src", "srcset", "poster":
						if strings.TrimSpace(attr.Val) != "" {
							urls = append(urls, attr.Val)
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return urls
}

type recordingAnnotationsRepo struct {
	items map[int64]annotations.Item
	saved []annotations.Item
}

func (r *recordingAnnotationsRepo) Save(_ context.Context, item *annotations.Item) error {
	if r.items == nil {
		r.items = map[int64]annotations.Item{}
	}
	if item.ID == 0 {
		item.ID = int64(len(r.items) + 1)
	}
	copied := *item
	r.items[item.ID] = copied
	r.saved = append(r.saved, copied)
	return nil
}

func (r *recordingAnnotationsRepo) SaveMany(ctx context.Context, items []annotations.Item) error {
	for i := range items {
		if err := r.Save(ctx, &items[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *recordingAnnotationsRepo) Update(_ context.Context, item *annotations.Item) error {
	if r.items == nil {
		r.items = map[int64]annotations.Item{}
	}
	copied := *item
	r.items[item.ID] = copied
	r.saved = append(r.saved, copied)
	return nil
}

func (r *recordingAnnotationsRepo) Find(_ context.Context, query *annotations.ItemQuery) ([]*annotations.ItemDTO, error) {
	if item, ok := r.items[query.AnnotationID]; ok {
		uid := item.DashboardUID
		return []*annotations.ItemDTO{{
			ID:           item.ID,
			DashboardID:  item.DashboardID,
			DashboardUID: &uid,
			Text:         item.Text,
			Tags:         item.Tags,
			Time:         item.Epoch,
			TimeEnd:      item.EpochEnd,
		}}, nil
	}
	return []*annotations.ItemDTO{}, nil
}

func (r *recordingAnnotationsRepo) Delete(_ context.Context, params *annotations.DeleteParams) error {
	delete(r.items, params.ID)
	return nil
}

func (r *recordingAnnotationsRepo) FindTags(_ context.Context, _ *annotations.TagsQuery) (annotations.FindTagsResult, error) {
	return annotations.FindTagsResult{}, nil
}
