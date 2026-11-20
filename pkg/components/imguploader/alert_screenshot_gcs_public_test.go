package imguploader_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/imguploader"
	"github.com/grafana/grafana/pkg/infra/log"
	ngimage "github.com/grafana/grafana/pkg/services/ngalert/image"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/screenshot"
	"github.com/grafana/grafana/pkg/setting"
)

// These tests are the spec for alert screenshots uploaded to Google Cloud
// Storage. They fail while the uploader publishes objects with the publicRead
// ACL, and they pass once a screenshot uploaded with the shipped default
// (signed URLs disabled, no separate opt-in to public objects) is not readable
// by an anonymous client at https://storage.googleapis.com/BUCKET/OBJECT.

const alertScreenshotBucket = "alert-screenshots"

func TestDefaultGCSConfigDoesNotPublishAlertScreenshot(t *testing.T) {
	// Shipped defaults.ini leaves enable_signed_urls false and does not offer
	// another switch for object ACLs. An administrator who selects the gcs
	// provider and a bucket, and leaves that default, must not publish the
	// rendered panel to anonymous readers.
	cfg := loadImageStorageConfig(t)
	cfg.ImageUploadProvider = "gcs"
	setGCSKey(t, cfg, "bucket", alertScreenshotBucket)
	setGCSKey(t, cfg, "path", "alerts")

	screenshot := []byte("panel-query-results-default-config")
	uploaded := uploadScreenshot(t, cfg, screenshot)

	assertAnonymousCannotReadScreenshot(t, uploaded, screenshot)
}

func TestSignedURLsDisabledDoesNotPublishAlertScreenshot(t *testing.T) {
	// The attack leaves enable_signed_urls at the documented value false.
	// That value is not an opt-in to public objects, and a key file does not
	// change the ACL decision.
	cfg := loadImageStorageConfig(t)
	cfg.ImageUploadProvider = "gcs"
	setGCSKey(t, cfg, "bucket", alertScreenshotBucket)
	setGCSKey(t, cfg, "path", "alerts/prod")
	setGCSKey(t, cfg, "key_file", writeEphemeralServiceAccount(t))
	setGCSKey(t, cfg, "enable_signed_urls", "false")

	screenshot := []byte("panel-query-results-signed-urls-disabled")
	uploaded := uploadScreenshot(t, cfg, screenshot)

	assertAnonymousCannotReadScreenshot(t, uploaded, screenshot)
}

func TestAlertingImageServiceDoesNotPublishGCSScreenshot(t *testing.T) {
	// ScreenshotImageService.NewImage is the alerting path that uploads the
	// rendered panel and stores the URL later copied into notifications.
	cfg := loadImageStorageConfig(t)
	cfg.ImageUploadProvider = "gcs"
	cfg.UnifiedAlerting.Screenshots.Capture = true
	cfg.UnifiedAlerting.Screenshots.UploadExternalImageStorage = true
	setGCSKey(t, cfg, "bucket", alertScreenshotBucket)
	setGCSKey(t, cfg, "path", "alerts")

	panelBytes := []byte("panel-query-results-alerting-service")
	dir := t.TempDir()
	diskPath := filepath.Join(dir, "panel.png")
	require.NoError(t, os.WriteFile(diskPath, panelBytes, 0o600))

	store := startGCS(t)
	uploader := newUploaderFromConfig(t, cfg)
	registry := prometheus.NewRegistry()
	dash := "ops-overview"
	panel := int64(3)
	svc := ngimage.NewScreenshotImageService(
		ngimage.NewInmemCacheService(time.Minute, registry),
		&screenshot.NoOpRateLimiter{},
		log.NewNopLogger(),
		fileScreenshotService{path: diskPath},
		5*time.Second,
		memoryImageStore{},
		ngimage.NewUploadingService(uploader, registry),
	)

	image, err := svc.NewImage(context.Background(), &models.AlertRule{
		OrgID:        1,
		DashboardUID: &dash,
		PanelID:      &panel,
	})
	require.NoError(t, err)
	require.NotNil(t, image)
	require.NotEmpty(t, image.URL)
	store.noteReturnedURL(image.URL)

	assertAnonymousCannotReadScreenshot(t, storedUpload{store: store, url: image.URL}, panelBytes)
}

func TestSignedGCSUploadDoesNotGrantAnonymousRead(t *testing.T) {
	cfg := loadImageStorageConfig(t)
	cfg.ImageUploadProvider = "gcs"
	setGCSKey(t, cfg, "bucket", alertScreenshotBucket)
	setGCSKey(t, cfg, "path", "alerts")
	setGCSKey(t, cfg, "key_file", writeEphemeralServiceAccount(t))
	setGCSKey(t, cfg, "enable_signed_urls", "true")

	screenshot := []byte("panel-query-results-signed")
	uploaded := uploadScreenshot(t, cfg, screenshot)

	assertAnonymousCannotReadScreenshot(t, uploaded, screenshot)
}

func TestPublicReadACLServesObjectWithoutCredentials(t *testing.T) {
	// The stand-in follows the objects.insert predefinedAcl contract shipped in
	// google.golang.org/api v0.297.0 and the public object URI contract: a
	// publicRead insert grants allUsers READER, and GET of
	// https://storage.googleapis.com/BUCKET/OBJECT needs no credentials.
	store := newFakeGCS()
	srv := httptest.NewServer(store)
	t.Cleanup(srv.Close)

	const (
		bucket = "contract-bucket"
		name   = "alerts/panel.png"
		body   = "public-object-bytes"
	)
	insertObject(t, srv.URL, bucket, name, "publicRead", []byte(body))

	status, got := anonymousGet(t, store, fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucket, name))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, body, string(got))

	insertObject(t, srv.URL, bucket, "alerts/private.png", "", []byte("hidden"))
	status, _ = anonymousGet(t, store, "https://storage.googleapis.com/"+bucket+"/alerts/private.png")
	require.Equal(t, http.StatusForbidden, status)
}

type storedUpload struct {
	store *fakeGCS
	url   string
}

func uploadScreenshot(t *testing.T, cfg *setting.Cfg, screenshot []byte) storedUpload {
	t.Helper()
	dir := t.TempDir()
	diskPath := filepath.Join(dir, "panel.png")
	require.NoError(t, os.WriteFile(diskPath, screenshot, 0o600))

	store := startGCS(t)
	uploader := newUploaderFromConfig(t, cfg)
	returned, err := uploader.Upload(context.Background(), diskPath)
	require.NoError(t, err)
	require.NotEmpty(t, returned)
	store.noteReturnedURL(returned)
	return storedUpload{store: store, url: returned}
}

func assertAnonymousCannotReadScreenshot(t *testing.T, uploaded storedUpload, screenshot []byte) {
	t.Helper()
	obj, ok := uploaded.store.objectForURL(uploaded.url)
	require.Truef(t, ok, "upload did not store the object named by %s; requests: %s", uploaded.url, uploaded.store.requestLog())

	publicURL := canonicalPublicURL(uploaded.url)
	status, body := anonymousGet(t, uploaded.store, publicURL)
	require.Falsef(t, status == http.StatusOK && bytes.Equal(body, screenshot),
		"anonymous GET %s returned the alert screenshot (predefinedAcl=%q acl=%s). The object must stay private unless an administrator explicitly opts into public objects",
		publicURL, obj.predefinedACL, obj.aclEntities)
}

func loadImageStorageConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: filepath.Join("..", "..", ".."),
	}))
	return cfg
}

func setGCSKey(t *testing.T, cfg *setting.Cfg, key, value string) {
	t.Helper()
	sec, err := cfg.Raw.GetSection("external_image_storage.gcs")
	require.NoError(t, err)
	sec.Key(key).SetValue(value)
}

func newUploaderFromConfig(t *testing.T, cfg *setting.Cfg) imguploader.ImageUploader {
	t.Helper()
	uploader, err := imguploader.NewImageUploader(cfg)
	require.NoError(t, err)
	return uploader
}

func startGCS(t *testing.T) *fakeGCS {
	t.Helper()
	store := newFakeGCS()
	srv := httptest.NewServer(store)
	t.Cleanup(srv.Close)
	// cloud.google.com/go/storage v1.67.1 NewClient reads this and disables
	// authentication, which is how the real uploader client reaches this server.
	t.Setenv("STORAGE_EMULATOR_HOST", srv.URL)
	return store
}

func writeEphemeralServiceAccount(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	raw, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "screenshot-uploader@example.com",
		"private_key":  string(pemKey),
	})
	require.NoError(t, err)
	name := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(name, raw, 0o600))
	return name
}

type fileScreenshotService struct {
	path string
}

func (s fileScreenshotService) Take(context.Context, screenshot.ScreenshotOptions) (*screenshot.Screenshot, error) {
	return &screenshot.Screenshot{Path: s.path}, nil
}

type memoryImageStore struct{}

func (memoryImageStore) GetImage(context.Context, string) (*models.Image, error) {
	return nil, models.ErrImageNotFound
}

func (memoryImageStore) GetImageByURL(context.Context, string) (*models.Image, error) {
	return nil, models.ErrImageNotFound
}

func (memoryImageStore) GetImages(context.Context, []string) ([]models.Image, []string, error) {
	return nil, nil, models.ErrImageNotFound
}

func (memoryImageStore) SaveImage(context.Context, *models.Image) error { return nil }

func (memoryImageStore) URLExists(context.Context, string) (bool, error) { return false, nil }

// fakeGCS is a stand-in for the Cloud Storage JSON API upload endpoint and for
// anonymous reads of https://storage.googleapis.com/BUCKET/OBJECT.
//
// Insert handling follows cloud.google.com/go/storage v1.67.1:
// Writer.PredefinedACL is copied into the objects.insert call
// (writer.go openWriter, http_client.go OpenWriter) and
// ObjectsInsertCall.PredefinedAcl sets the predefinedAcl query parameter
// (google.golang.org/api v0.297.0 storage/v1/storage-gen.go).
//
// publicRead grants allUsers READER. A GET of the public object URI with no
// Authorization header returns the object bytes. Any other ACL does not.
type fakeGCS struct {
	mu       sync.Mutex
	objects  map[string]storedObject
	requests []string
}

type storedObject struct {
	data          []byte
	predefinedACL string
	aclEntities   string
	anonymous     bool
}

func newFakeGCS() *fakeGCS {
	return &fakeGCS{objects: map[string]storedObject{}}
}

func (s *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
	s.mu.Unlock()

	if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/upload/storage/v1/b/") {
		http.Error(w, "unsupported storage request", http.StatusNotImplemented)
		return
	}
	bucket, name, data, predefinedACL, aclEntities, ok := parseInsert(r, body)
	if !ok || bucket == "" || name == "" {
		http.Error(w, "could not parse objects.insert", http.StatusBadRequest)
		return
	}
	anonymous := predefinedACL == "publicRead" || grantsAllUsersReader(aclEntities)
	s.mu.Lock()
	s.objects[bucket+"/"+name] = storedObject{
		data:          data,
		predefinedACL: predefinedACL,
		aclEntities:   aclEntities,
		anonymous:     anonymous,
	}
	s.mu.Unlock()

	sum := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
	buf := []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
	resp := map[string]any{
		"bucket":      bucket,
		"name":        name,
		"size":        fmt.Sprintf("%d", len(data)),
		"contentType": "image/png",
		"crc32c":      base64.StdEncoding.EncodeToString(buf),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func parseInsert(r *http.Request, body []byte) (bucket, name string, data []byte, predefinedACL, aclEntities string, ok bool) {
	bucket, objectFromPath, pathOK := bucketAndObject(r.URL.Path)
	if !pathOK {
		return "", "", nil, "", "", false
	}
	q := r.URL.Query()
	predefinedACL = q.Get("predefinedAcl")
	name = q.Get("name")
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return bucket, name, body, predefinedACL, "", name != ""
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", "", nil, "", "", false
			}
			partBody, err := io.ReadAll(part)
			if err != nil {
				return "", "", nil, "", "", false
			}
			partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if partType == "application/json" || (name == "" && json.Valid(partBody)) {
				var meta struct {
					Name string `json:"name"`
					ACL  []struct {
						Entity string `json:"entity"`
						Role   string `json:"role"`
					} `json:"acl"`
				}
				if json.Unmarshal(partBody, &meta) == nil {
					if meta.Name != "" {
						name = meta.Name
					}
					var entities []string
					for _, rule := range meta.ACL {
						entities = append(entities, rule.Entity+":"+rule.Role)
					}
					aclEntities = strings.Join(entities, ",")
				}
				continue
			}
			data = partBody
		}
	} else {
		data = body
	}
	if name == "" {
		name = objectFromPath
	}
	return bucket, name, data, predefinedACL, aclEntities, true
}

func bucketAndObject(urlPath string) (string, string, bool) {
	const marker = "/b/"
	i := strings.Index(urlPath, marker)
	if i < 0 {
		return "", "", false
	}
	rest := strings.Trim(urlPath[i+len(marker):], "/")
	bucket, object, found := strings.Cut(rest, "/o/")
	if !found {
		bucket, _, found = strings.Cut(rest, "/o")
		if !found {
			return "", "", false
		}
		return bucket, "", true
	}
	return bucket, object, true
}

func grantsAllUsersReader(entities string) bool {
	for _, rule := range strings.Split(entities, ",") {
		entity, role, found := strings.Cut(rule, ":")
		if found && entity == "allUsers" && strings.EqualFold(role, "READER") {
			return true
		}
	}
	return false
}

func (s *fakeGCS) objectForURL(rawURL string) (storedObject, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, name, ok := publicURLParts(rawURL)
	if !ok {
		return storedObject{}, false
	}
	obj, found := s.objects[bucket+"/"+name]
	return obj, found
}

func (s *fakeGCS) noteReturnedURL(rawURL string) {
	s.mu.Lock()
	s.requests = append(s.requests, "returned "+rawURL)
	s.mu.Unlock()
}

func (s *fakeGCS) requestLog() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.requests, " | ")
}

func publicURLParts(rawURL string) (string, string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}
	trimmed := strings.TrimPrefix(parsed.EscapedPath(), "/")
	bucket, name, found := strings.Cut(trimmed, "/")
	if !found || bucket == "" || name == "" {
		return "", "", false
	}
	unescaped, err := url.PathUnescape(name)
	if err != nil {
		return "", "", false
	}
	return bucket, unescaped, true
}

func canonicalPublicURL(rawURL string) string {
	bucket, name, ok := publicURLParts(rawURL)
	if !ok {
		return rawURL
	}
	// Signed URLs may use another host. Anonymous access is decided on the
	// stable public object URI, with the signature removed.
	return "https://storage.googleapis.com/" + bucket + "/" + name
}

func anonymousGet(t *testing.T, store *fakeGCS, rawURL string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: store}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func (s *fakeGCS) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "storage.googleapis.com" {
		return nil, fmt.Errorf("anonymous client refused %s", req.URL.String())
	}
	if req.Header.Get("Authorization") != "" {
		return nil, fmt.Errorf("anonymous client sent credentials")
	}
	bucket, name, ok := publicURLParts(req.URL.String())
	if !ok {
		return httpResponse(http.StatusNotFound, []byte("missing object")), nil
	}
	s.mu.Lock()
	obj, found := s.objects[bucket+"/"+name]
	s.mu.Unlock()
	if !found || !obj.anonymous {
		return httpResponse(http.StatusForbidden, []byte("forbidden")), nil
	}
	return httpResponse(http.StatusOK, obj.data), nil
}

func httpResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d", status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    &http.Request{URL: &url.URL{}},
	}
}

func insertObject(t *testing.T, endpoint, bucket, name, predefinedACL string, data []byte) {
	t.Helper()
	q := url.Values{}
	q.Set("uploadType", "multipart")
	q.Set("name", name)
	if predefinedACL != "" {
		q.Set("predefinedAcl", predefinedACL)
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	meta, err := writer.CreatePart(textprotoMIME("application/json"))
	require.NoError(t, err)
	_, err = meta.Write([]byte(`{"name":"` + name + `"}`))
	require.NoError(t, err)
	media, err := writer.CreatePart(textprotoMIME("image/png"))
	require.NoError(t, err)
	_, err = media.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	reqURL := endpoint + "/upload/storage/v1/b/" + bucket + "/o?" + q.Encode()
	req, err := http.NewRequest(http.MethodPost, reqURL, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(respBody))
}

func textprotoMIME(contentType string) map[string][]string {
	return map[string][]string{"Content-Type": {contentType}}
}
