package image

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	alertingImages "github.com/grafana/alerting/images"
	alertingModels "github.com/grafana/alerting/models"

	"github.com/grafana/grafana/pkg/components/imguploader"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/screenshot"
	"github.com/grafana/grafana/pkg/setting"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// maxPresignedURLLifetime is the longest anonymous read this test accepts on a
// notification URL. It matches the uploader's existing presign default. A
// public object has no such bound: the URL keeps working until the object is
// deleted.
const maxPresignedURLLifetime = 7 * 24 * time.Hour

// TestAlertScreenshotS3URLIsNotWorldReadable drives the alert screenshot upload
// with external image storage set to S3 and presigned URLs left at the default.
// The URL that notifications receive must not grant an anonymous read for the
// life of the object.
func TestAlertScreenshotS3URLIsNotWorldReadable(t *testing.T) {
	t.Run("presigned URLs omitted", func(t *testing.T) {
		assertAlertScreenshotIsNotWorldReadable(t, true)
	})
	t.Run("presigned URLs explicitly disabled", func(t *testing.T) {
		assertAlertScreenshotIsNotWorldReadable(t, false)
	})
}

func assertAlertScreenshotIsNotWorldReadable(t *testing.T, omitPresignSetting bool) {
	t.Helper()

	s3srv := newACLHonoringS3(t)
	cfg := s3ScreenshotCfg(t, s3srv.URL, omitPresignSetting)

	// Same gates and constructor ScreenshotImageService uses once an
	// administrator enables capture and external upload.
	require.True(t, cfg.UnifiedAlerting.Screenshots.Capture)
	require.True(t, cfg.UnifiedAlerting.Screenshots.UploadExternalImageStorage)
	uploader, err := imguploader.NewImageUploader(cfg)
	require.NoError(t, err)
	uploads := NewUploadingService(uploader, prometheus.NewRegistry())

	shot := filepath.Join(t.TempDir(), "panel.png")
	require.NoError(t, os.WriteFile(shot, []byte("panel-png"), 0o600))

	images := store.NewFakeImageStore(t)
	svc := NewScreenshotImageService(
		&NoOpCacheService{},
		&screenshot.NoOpRateLimiter{},
		log.NewNopLogger(),
		pathScreenshotService{path: shot},
		5*time.Second,
		images,
		uploads,
	)

	ctx := context.Background()
	image, err := svc.NewImage(ctx, &models.AlertRule{
		OrgID:        1,
		UID:          "cpu-high",
		DashboardUID: new("dash"),
		PanelID:      new(int64(7)),
	})
	require.NoError(t, err)
	require.NotEmpty(t, image.URL)

	// The upload URL is what Alertmanager annotations and the image store hand
	// to notifiers.
	appURL, err := url.Parse("http://grafana.example")
	require.NoError(t, err)
	postable := state.StateToPostableAlert(state.StateTransition{
		State: &state.State{
			OrgID:        1,
			AlertRuleUID: "cpu-high",
			State:        eval.Alerting,
			Image:        image,
			Labels:       data.Labels{"alertname": "CPUHigh"},
			Annotations:  map[string]string{},
			StartsAt:     time.Now().Add(-time.Minute),
			EndsAt:       time.Now().Add(time.Hour),
		},
		PreviousState: eval.Normal,
	}, appURL)
	noted := string(postable.Annotations[alertingModels.ImageURLAnnotation])
	require.Equal(t, image.URL, noted)

	stored, err := images.GetImage(ctx, image.Token)
	require.NoError(t, err)
	require.Equal(t, image.URL, stored.URL)

	amAlert := types.Alert{Alert: model.Alert{Annotations: model.LabelSet{}}}
	for k, v := range postable.Annotations {
		amAlert.Annotations[model.LabelName(k)] = model.LabelValue(v)
	}
	require.Equal(t, image.URL, alertingImages.GetImageURL(amAlert))

	assertObjectIsNotWorldReadable(t, s3srv, image.URL)
}

// TestS3MultipartUploadIsNotWorldReadable covers the other write the same
// uploader performs once the PNG is larger than the SDK's part size.
// CreateMultipartUpload carries the canned ACL; UploadPart does not.
func TestS3MultipartUploadIsNotWorldReadable(t *testing.T) {
	s3srv := newACLHonoringS3(t)
	cfg := s3ScreenshotCfg(t, s3srv.URL, true)
	uploader, err := imguploader.NewImageUploader(cfg)
	require.NoError(t, err)

	shot := filepath.Join(t.TempDir(), "large-panel.png")
	// manager.MinUploadPartSize is the default part size. One extra byte forces
	// CreateMultipartUpload instead of a single PutObject.
	payload := make([]byte, manager.MinUploadPartSize+1)
	payload[0] = 0x89
	require.NoError(t, os.WriteFile(shot, payload, 0o600))

	got, err := uploader.Upload(context.Background(), shot)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	require.NotEmpty(t, s3srv.multipartACLs(), "large screenshot did not use multipart upload")

	assertObjectIsNotWorldReadable(t, s3srv, got)
}

func assertObjectIsNotWorldReadable(t *testing.T, s3srv *aclS3, notificationURL string) {
	t.Helper()

	parsed, err := url.Parse(notificationURL)
	require.NoError(t, err)

	bare := *parsed
	bare.RawQuery = ""
	bareResp := s3srv.get(t, bare.String())
	require.Equalf(t, http.StatusForbidden, bareResp.status,
		"anonymous GET of %s returned %d (body %q); write ACLs were %s. A public-read object stays readable, without credentials, until it is deleted",
		bare.String(), bareResp.status, preview(bareResp.body), s3srv.aclSummary())

	expires, err := strconv.Atoi(parsed.Query().Get("X-Amz-Expires"))
	require.NoErrorf(t, err, "notification URL %q has no X-Amz-Expires", notificationURL)
	require.Greater(t, expires, 0)
	require.LessOrEqual(t, time.Duration(expires)*time.Second, maxPresignedURLLifetime)

	notedResp := s3srv.get(t, notificationURL)
	require.Equalf(t, http.StatusOK, notedResp.status,
		"notification URL %s was not readable (status %d body %q)", notificationURL, notedResp.status, preview(notedResp.body))

	for _, acl := range s3srv.writeACLs() {
		require.NotContains(t, []string{"public-read", "public-read-write"}, acl)
	}
}

func s3ScreenshotCfg(t *testing.T, endpoint string, omitPresignSetting bool) *setting.Cfg {
	t.Helper()
	// Keep the SDK off the instance metadata service and any ambient credentials.
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "aws-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "aws-credentials"))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../../../"}))

	cfg.ImageUploadProvider = "s3"
	cfg.UnifiedAlerting.Screenshots.Capture = true
	cfg.UnifiedAlerting.Screenshots.UploadExternalImageStorage = true

	sec, err := cfg.Raw.GetSection("external_image_storage.s3")
	require.NoError(t, err)
	setIniKey(t, sec, "endpoint", endpoint)
	setIniKey(t, sec, "path_style_access", "true")
	setIniKey(t, sec, "bucket", "alert-screenshots")
	setIniKey(t, sec, "region", "us-east-1")
	setIniKey(t, sec, "access_key", "test-access-key")
	setIniKey(t, sec, "secret_key", "test-secret-key")
	if omitPresignSetting {
		sec.DeleteKey("enable_presigned_urls")
	}
	require.False(t, sec.Key("enable_presigned_urls").MustBool(false))
	return cfg
}

func setIniKey(t *testing.T, sec *ini.Section, name, value string) {
	t.Helper()
	if sec.HasKey(name) {
		sec.Key(name).SetValue(value)
		return
	}
	_, err := sec.NewKey(name, value)
	require.NoError(t, err)
}

type pathScreenshotService struct {
	path string
}

func (s pathScreenshotService) Take(context.Context, screenshot.ScreenshotOptions) (*screenshot.Screenshot, error) {
	return &screenshot.Screenshot{Path: s.path}, nil
}

// aclS3 is a stand-in for the S3 writes and reads the uploader performs.
// It stores the canned ACL from the x-amz-acl header the AWS SDK serializes,
// and answers GET the way the S3 canned-ACL table does:
// public-read and public-read-write grant AllUsers READ, so an unsigned request
// is allowed; every other canned ACL, including a missing header, leaves the
// object private. A presigned GET is allowed only while X-Amz-Expires, measured
// from X-Amz-Date, has not elapsed, and only when the signer attached the
// query fields it always writes.
type aclS3 struct {
	t       *testing.T
	URL     string
	server  *httptest.Server
	mu      sync.Mutex
	objects map[string]*storedObject
	uploads map[string]*openUpload
	writes  []string
	multi   []string
}

type storedObject struct {
	acl  string
	body []byte
}

type openUpload struct {
	acl   string
	parts map[int][]byte
}

type httpResult struct {
	status int
	body   string
}

func newACLHonoringS3(t *testing.T) *aclS3 {
	t.Helper()
	s := &aclS3{
		t:       t,
		objects: map[string]*storedObject{},
		uploads: map[string]*openUpload{},
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	s.server = srv
	return s
}

func (s *aclS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut && q.Get("uploadId") != "" && q.Get("partNumber") != "":
		s.uploadPart(w, r)
	case r.Method == http.MethodPost && q.Has("uploads"):
		s.createMultipart(w, r)
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		s.completeMultipart(w, r)
	case r.Method == http.MethodPut:
		s.putObject(w, r)
	case r.Method == http.MethodGet:
		s.getObject(w, r)
	default:
		http.Error(w, "unsupported "+r.Method+" "+r.URL.RequestURI(), http.StatusBadRequest)
	}
}

func (s *aclS3) putObject(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acl := r.Header.Get("X-Amz-Acl")
	s.mu.Lock()
	s.objects[r.URL.Path] = &storedObject{acl: acl, body: body}
	s.writes = append(s.writes, acl)
	s.mu.Unlock()
	w.Header().Set("ETag", `"put-etag"`)
	w.WriteHeader(http.StatusOK)
}

func (s *aclS3) createMultipart(w http.ResponseWriter, r *http.Request) {
	acl := r.Header.Get("X-Amz-Acl")
	const uploadID = "upload-1"
	s.mu.Lock()
	s.uploads[uploadID] = &openUpload{acl: acl, parts: map[int][]byte{}}
	s.writes = append(s.writes, acl)
	s.multi = append(s.multi, acl)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>alert-screenshots</Bucket><Key>`+
		xmlEscape(strings.TrimPrefix(r.URL.Path, "/alert-screenshots/"))+
		`</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
}

func (s *aclS3) uploadPart(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	part, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	up := s.uploads[r.URL.Query().Get("uploadId")]
	if up != nil {
		up.parts[part] = body
	}
	s.mu.Unlock()
	w.Header().Set("ETag", `"part-etag"`)
	w.WriteHeader(http.StatusOK)
}

func (s *aclS3) completeMultipart(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	id := r.URL.Query().Get("uploadId")
	s.mu.Lock()
	up := s.uploads[id]
	if up == nil {
		s.mu.Unlock()
		http.Error(w, "unknown upload", http.StatusNotFound)
		return
	}
	var body []byte
	for i := 1; i <= len(up.parts); i++ {
		body = append(body, up.parts[i]...)
	}
	s.objects[r.URL.Path] = &storedObject{acl: up.acl, body: body}
	delete(s.uploads, id)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Bucket>alert-screenshots</Bucket><Key>`+
		xmlEscape(strings.TrimPrefix(r.URL.Path, "/alert-screenshots/"))+
		`</Key><ETag>"complete-etag"</ETag></CompleteMultipartUploadResult>`)
}

func (s *aclS3) getObject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	obj := s.objects[r.URL.Path]
	s.mu.Unlock()
	if obj == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !anonymousMayRead(obj.acl, r, time.Now()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(obj.body)
}

func (s *aclS3) get(t *testing.T, rawURL string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	resp, err := s.server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return httpResult{status: resp.StatusCode, body: string(body)}
}

func (s *aclS3) writeACLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.writes))
	copy(out, s.writes)
	return out
}

func (s *aclS3) multipartACLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.multi))
	copy(out, s.multi)
	return out
}

func (s *aclS3) aclSummary() string {
	acls := s.writeACLs()
	if len(acls) == 0 {
		return "(no write)"
	}
	return "[" + strings.Join(acls, ", ") + "]"
}

// anonymousMayRead applies the S3 canned ACL grants for an unsigned caller.
// public-read and public-read-write give the AllUsers group READ, and AllUsers
// includes unsigned requests. A missing ACL is the default private ACL: the
// owner has FULL_CONTROL and nobody else can read. Presigned requests are
// unsigned too, but they carry the query fields the SigV4 presigner writes;
// those are honored only until X-Amz-Date plus X-Amz-Expires.
func anonymousMayRead(acl string, r *http.Request, now time.Time) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != "" || q.Get("X-Amz-Signature") != "" {
		return presignAllows(q, now)
	}
	switch acl {
	case "public-read", "public-read-write":
		return true
	default:
		return false
	}
}

func presignAllows(q url.Values, now time.Time) bool {
	if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return false
	}
	if q.Get("X-Amz-Credential") == "" || q.Get("X-Amz-SignedHeaders") == "" || q.Get("X-Amz-Signature") == "" {
		return false
	}
	issued, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	exp, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || exp <= 0 {
		return false
	}
	return now.Before(issued.Add(time.Duration(exp) * time.Second))
}

func preview(body string) string {
	const max = 64
	if len(body) <= max {
		return body
	}
	return body[:max] + "..."
}

func xmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(s)
}
