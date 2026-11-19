package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/oam"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// accountLookupPageLimit is the most ListSinks or ListAttachedLinks requests one
// GetAccountsForCurrentUserOrRole call may make when the service keeps returning
// a next token. accountLookupItemLimit is the most accounts that call may return.
const (
	accountLookupPageLimit = 20
	accountLookupItemLimit = 1000
)

// offeredAccountPages is how many pages the stand-in keeps returning before it
// finally omits NextToken. It is larger than accountLookupPageLimit so a lookup
// that follows every page fails the test instead of hanging it.
const offeredAccountPages = 40

func TestAccountLookupStopsOnEmptyNextToken(t *testing.T) {
	t.Run("ListSinks", func(t *testing.T) {
		var sinks atomic.Int32
		client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ListSinks":
				n := sinks.Add(1)
				// A non-nil empty token is the end of the result, same as an omitted token.
				// Keep offering it past the cap so a loop that treats "" as another page
				// is observable.
				if n > offeredAccountPages {
					writeOAM(t, w, oamPage{sink: true})
					return
				}
				writeOAM(t, w, oamPage{sink: true, includeNext: true, next: ""})
			case "/ListAttachedLinks":
				writeOAM(t, w, oamPage{})
			default:
				http.NotFound(w, r)
			}
		})

		_, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(context.Background())
		require.NoError(t, err)
		require.Equal(t, int32(1), sinks.Load(), "ListSinks empty NextToken must end the walk")
	})

	t.Run("ListAttachedLinks", func(t *testing.T) {
		var links atomic.Int32
		client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ListSinks":
				writeOAM(t, w, oamPage{sink: true})
			case "/ListAttachedLinks":
				n := links.Add(1)
				if n > offeredAccountPages {
					writeOAM(t, w, oamPage{link: true})
					return
				}
				writeOAM(t, w, oamPage{link: true, includeNext: true, next: ""})
			default:
				http.NotFound(w, r)
			}
		})

		_, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(context.Background())
		require.NoError(t, err)
		require.Equal(t, int32(1), links.Load(), "ListAttachedLinks empty NextToken must end the walk")
	})
}

func TestAccountLookupCapsChangingNextToken(t *testing.T) {
	t.Run("ListSinks", func(t *testing.T) {
		var sinks atomic.Int32
		client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ListSinks" {
				http.NotFound(w, r)
				return
			}
			n := sinks.Add(1)
			if n > offeredAccountPages {
				writeOAM(t, w, oamPage{sink: true})
				return
			}
			writeOAM(t, w, oamPage{sink: true, includeNext: true, next: fmt.Sprintf("sink-page-%d", n)})
		})

		_, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(context.Background())
		if err != nil {
			require.LessOrEqual(t, sinks.Load(), int32(accountLookupPageLimit))
			return
		}
		require.LessOrEqual(t, sinks.Load(), int32(accountLookupPageLimit))
	})

	t.Run("ListAttachedLinks", func(t *testing.T) {
		var links atomic.Int32
		client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ListSinks":
				writeOAM(t, w, oamPage{sink: true})
			case "/ListAttachedLinks":
				n := links.Add(1)
				if n > offeredAccountPages {
					writeOAM(t, w, oamPage{link: true})
					return
				}
				writeOAM(t, w, oamPage{link: true, includeNext: true, next: fmt.Sprintf("link-page-%d", n)})
			default:
				http.NotFound(w, r)
			}
		})

		_, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(context.Background())
		if err != nil {
			require.LessOrEqual(t, links.Load(), int32(accountLookupPageLimit))
			return
		}
		require.LessOrEqual(t, links.Load(), int32(accountLookupPageLimit))
	})
}

func TestAccountLookupCapsRetainedAccounts(t *testing.T) {
	const perPage = 400
	const pages = 3
	client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ListSinks":
			writeOAM(t, w, oamPage{sink: true})
		case "/ListAttachedLinks":
			var req struct {
				NextToken *string `json:"NextToken"`
			}
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			if len(body) > 0 {
				require.NoError(t, json.Unmarshal(body, &req))
			}
			page := 0
			if req.NextToken != nil {
				_, scanErr := fmt.Sscanf(*req.NextToken, "links-%d", &page)
				require.NoError(t, scanErr)
			}
			next := ""
			includeNext := page+1 < pages
			if includeNext {
				next = fmt.Sprintf("links-%d", page+1)
			}
			items := make([]map[string]string, 0, perPage)
			for i := 0; i < perPage; i++ {
				id := 200000000000 + page*perPage + i
				items = append(items, map[string]string{
					"Label":   fmt.Sprintf("link-%d", id),
					"LinkArn": fmt.Sprintf("arn:aws:oam:us-east-1:%d:link/id", id),
				})
			}
			payload := map[string]any{"Items": items}
			if includeNext {
				payload["NextToken"] = next
			}
			writeJSON(t, w, payload)
		default:
			http.NotFound(w, r)
		}
	})

	accounts, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(context.Background())
	if err != nil {
		return
	}
	require.LessOrEqual(t, len(accounts), accountLookupItemLimit)
}

func TestAccountLookupReturnsWhenContextCancelled(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	client := newOAMClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-release:
			return
		}
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	errCh := make(chan error, 1)
	go func() {
		_, err := NewAccountsService(client).GetAccountsForCurrentUserOrRole(ctx)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("GetAccountsForCurrentUserOrRole kept running after its context was cancelled")
	}
}

type oamPage struct {
	sink        bool
	link        bool
	includeNext bool
	next        string
}

func writeOAM(t *testing.T, w http.ResponseWriter, page oamPage) {
	t.Helper()
	payload := map[string]any{}
	if page.sink {
		payload["Items"] = []map[string]string{{
			"Name": "monitoring",
			"Arn":  "arn:aws:oam:us-east-1:111111111111:sink/monitoring",
		}}
	}
	if page.link {
		payload["Items"] = []map[string]string{{
			"Label":   "linked",
			"LinkArn": "arn:aws:oam:us-east-1:222222222222:link/linked",
		}}
	}
	if page.includeNext {
		payload["NextToken"] = page.next
	}
	writeJSON(t, w, payload)
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}

func newOAMClient(t *testing.T, handler http.HandlerFunc) models.OAMAPIProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return oam.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})
}
