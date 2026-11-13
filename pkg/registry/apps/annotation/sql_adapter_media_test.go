package annotation

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/annotations"
)

func TestSQLAdapterDoesNotStoreLoadableMedia(t *testing.T) {
	repo := &mediaRecordingRepo{}
	adapter := NewSQLAdapter(repo, nil, annotations.CleanupSettings{})
	markup := `deploy note <img src="/profile/switch-org/2" alt=""><audio src="/profile/switch-org/2"></audio>`
	ctx := identity.WithRequester(t.Context(), &identity.StaticRequester{OrgID: 1})

	for _, call := range []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := adapter.Create(ctx, &annotationV0.Annotation{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
					Spec:       annotationV0.AnnotationSpec{Text: markup, Time: 1},
				})
				return err
			},
		},
		{
			name: "update",
			run: func() error {
				_, err := adapter.Update(ctx, &annotationV0.Annotation{
					ObjectMeta: metav1.ObjectMeta{Name: "a-1", Namespace: "default"},
					Spec:       annotationV0.AnnotationSpec{Text: markup, Time: 1},
				})
				return err
			},
		},
	} {
		t.Run(call.name, func(t *testing.T) {
			repo.saved = nil
			require.NoError(t, call.run())
			require.NotEmpty(t, repo.saved)
			for _, item := range repo.saved {
				require.Empty(t, annotationMediaResourceURLs(item.Text), "stored text %q", item.Text)
			}
		})
	}
}

func annotationMediaResourceURLs(markup string) []string {
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

type mediaRecordingRepo struct {
	saved []annotations.Item
}

func (r *mediaRecordingRepo) Save(_ context.Context, item *annotations.Item) error {
	r.saved = append(r.saved, *item)
	return nil
}

func (r *mediaRecordingRepo) SaveMany(_ context.Context, items []annotations.Item) error {
	r.saved = append(r.saved, items...)
	return nil
}

func (r *mediaRecordingRepo) Update(_ context.Context, item *annotations.Item) error {
	r.saved = append(r.saved, *item)
	return nil
}

func (r *mediaRecordingRepo) Find(context.Context, *annotations.ItemQuery) ([]*annotations.ItemDTO, error) {
	return nil, nil
}

func (r *mediaRecordingRepo) Delete(context.Context, *annotations.DeleteParams) error { return nil }

func (r *mediaRecordingRepo) FindTags(context.Context, *annotations.TagsQuery) (annotations.FindTagsResult, error) {
	return annotations.FindTagsResult{}, nil
}
