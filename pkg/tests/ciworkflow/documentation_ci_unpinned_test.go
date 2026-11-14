package ciworkflow_test

// These tests reproduce the documentation CI job at
// .github/workflows/documentation-ci.yml. They fail while that job runs a
// mutable container tag or a mutable action ref with a token that can create
// pull request review comments, and they pass once that mutable reference can
// no longer be what the job executes.
//
// The container commands follow actions/runner v2.338.2
// (commit d1eb12d4b115c301201de27d667284e1a80f2ab5):
// DockerCommandManager.DockerPull passes the image string to `docker pull`,
// MountWellKnownDirectories replaces the image entrypoint with `tail -f /dev/null`,
// and StepHost.ExecuteAsync runs `docker exec -e KEY` with the step environment
// so the value of GITHUB_TOKEN comes from the docker client's environment.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

const placeholderToken = "PLACEHOLDER_GITHUB_TOKEN"

// createReviewCommentRoute is the route actions/github-script's Octokit client
// calls for pulls.createReviewComment (@octokit/plugin-rest-endpoint-methods
// 10.0.1, dist-src/generated/endpoints.js). server-to-server-permissions.json
// from github/docs (fpt-2026-03-10) lists this route at access "write" under
// the pull_requests permission.
const createReviewCommentRoute = "POST /repos/grafana/grafana/pulls/1/comments"

func TestDocumentationCIMutableValeImageCannotCreateReviewComment(t *testing.T) {
	job := loadDocumentationValeJob(t)
	if !docsPullRequestStartsJob(job) {
		t.Fatal("documentation-ci.yml no longer starts the vale job for a pull request that changes docs/sources")
	}

	reg := startRegistry(t)
	api := startReviewAPI(t)
	attacker := importImage(t, rootfs(t, attackerVale(api.url)))
	benign := importImage(t, rootfs(t, benignVale))

	// A tag is whatever the registry last pushed under that name. The benign
	// image is also stored under its digest so a pinned reference can ignore
	// a later move of the tag.
	benignDigest, err := reg.push(benign, "grafana/vale", "pinned")
	if err != nil {
		t.Fatalf("push pinned image: %v", err)
	}
	if _, err := reg.push(attacker, "grafana/vale", "latest"); err != nil {
		t.Fatalf("push attacker over latest: %v", err)
	}

	image := job.image
	var pulled string
	if digestPinned(image) {
		pulled = reg.url + "/grafana/vale@" + benignDigest
	} else {
		repo, tag := imageRepoAndTag(image)
		if repo != "grafana/vale" || tag == "" {
			t.Fatalf("image %q is not a digest pin and is not grafana/vale:<tag>", image)
		}
		pulled = reg.ref("grafana/vale", tag)
	}

	comment := runJobContainer(t, pulled, valeStepScript, api)
	if comment.created {
		t.Fatalf("mutable image %q ran inside the vale job and created a pull request review comment with the workflow token", image)
	}
	if !digestPinned(image) {
		t.Fatalf("image %q is not pinned to a digest, but the substituted tag did not create a review comment", image)
	}
}

func TestDocumentationCIMutableValeActionCannotCreateReviewComment(t *testing.T) {
	job := loadDocumentationValeJob(t)
	if !docsPullRequestStartsJob(job) {
		t.Fatal("documentation-ci.yml no longer starts the vale job for a pull request that changes docs/sources")
	}
	if job.actionRepo != "grafana/writers-toolkit/vale-action" {
		t.Fatalf("vale step uses %q, want the writers-toolkit vale-action", job.actionRepo)
	}

	repo := initActionRepo(t)
	api := startReviewAPI(t)
	reg := startRegistry(t)
	image := importImage(t, rootfs(t, benignVale))
	if _, err := reg.push(image, "grafana/vale", "pinned"); err != nil {
		t.Fatalf("push benign image: %v", err)
	}

	// Move the tag the workflow would follow. A full commit SHA stays on the
	// commit that was already recorded.
	var script string
	if shaPinned(job.actionRef) {
		pinned := gitRevParse(t, repo, "HEAD")
		moveRef(t, repo, "vale-action/v2", attackerActionScript)
		if gitRevParse(t, repo, pinned) != pinned {
			t.Fatalf("commit SHA changed when a tag moved")
		}
		script = readRefScript(t, repo, pinned)
	} else {
		moveRef(t, repo, job.actionRef, attackerActionScript)
		script = readRefScript(t, repo, job.actionRef)
	}
	comment := runJobContainer(t, reg.ref("grafana/vale", "pinned"), script, api)
	if comment.created {
		t.Fatalf("action ref %q resolved to a commit that created a pull request review comment with the workflow token", job.actionRef)
	}
	if !shaPinned(job.actionRef) {
		t.Fatalf("action ref %q is not a full commit SHA, but the moved ref did not create a review comment", job.actionRef)
	}
}

func TestForkedDocsPullRequestDoesNotKeepPullRequestWrite(t *testing.T) {
	job := loadDocumentationValeJob(t)
	access := tokenPermissions(job, true)
	if access["pull-requests"] == "write" {
		t.Fatal("fork pull_request kept pull-requests: write; workflow-syntax downgrades write to read")
	}
	if allowsCreateReviewComment(access) {
		t.Fatal("fork token was allowed to create a review comment")
	}
}

type valeJob struct {
	image      string
	actionRepo string
	actionRef  string
	tokenInput string
	perms      map[string]string
	paths      []string
	branches   []string
	hasPR      bool
}

func loadDocumentationValeJob(t *testing.T) valeJob {
	t.Helper()
	path := filepath.Join(repoRoot(t), ".github", "workflows", "documentation-ci.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := mapping(&doc)
	on := child(root, "on")
	pr := child(on, "pull_request")
	jobNode := child(child(root, "jobs"), "vale")
	if jobNode == nil {
		t.Fatal("jobs.vale is missing")
	}
	perms := stringMap(child(jobNode, "permissions"))
	if len(perms) == 0 {
		perms = stringMap(child(root, "permissions"))
	}
	image := scalar(child(child(jobNode, "container"), "image"))
	if image == "" {
		image = scalar(child(jobNode, "container"))
	}
	var actionRepo, actionRef, tokenInput string
	steps := child(jobNode, "steps")
	if steps != nil && steps.Kind == yaml.SequenceNode {
		for _, step := range steps.Content {
			uses := scalar(child(step, "uses"))
			if strings.Contains(uses, "vale-action@") {
				actionRepo, actionRef = splitAction(uses)
				tokenInput = scalar(child(child(step, "with"), "token"))
			}
		}
	}
	if actionRepo == "" {
		t.Fatal("vale job does not use vale-action")
	}
	return valeJob{
		image:      image,
		actionRepo: actionRepo,
		actionRef:  actionRef,
		tokenInput: tokenInput,
		perms:      perms,
		paths:      stringList(child(pr, "paths")),
		branches:   stringList(child(pr, "branches")),
		hasPR:      pr != nil,
	}
}

func docsPullRequestStartsJob(job valeJob) bool {
	if !job.hasPR {
		return false
	}
	if len(job.branches) > 0 && !contains(job.branches, "main") {
		return false
	}
	if len(job.paths) == 0 {
		return true
	}
	for _, pattern := range job.paths {
		if githubPathMatch(pattern, "docs/sources/index.md") {
			return true
		}
	}
	return false
}

func githubPathMatch(pattern, file string) bool {
	if pattern == file {
		return true
	}
	// GitHub's ** crosses directories. A trailing /** matches the directory itself too.
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if file == prefix || strings.HasPrefix(file, prefix+"/") {
			return true
		}
	}
	ok, err := pathMatchGitHub(pattern, file)
	return err == nil && ok
}

func pathMatchGitHub(pattern, file string) (bool, error) {
	return filepath.Match(pattern, file)
}

func tokenPermissions(job valeJob, fromFork bool) map[string]string {
	out := map[string]string{}
	for k, v := range job.perms {
		out[k] = v
	}
	// workflow-syntax.md "How permissions are calculated for a workflow job":
	// a pull_request from a fork downgrades every write permission to read
	// unless the repository sends write tokens to workflows from pull requests.
	// This test models the default, where that setting is not selected.
	if fromFork {
		for k, v := range out {
			if v == "write" {
				out[k] = "read"
			}
		}
	}
	return out
}

func allowsCreateReviewComment(access map[string]string) bool {
	return access["pull-requests"] == "write"
}

func digestPinned(image string) bool {
	return regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image)
}

func shaPinned(ref string) bool {
	return regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ref)
}

func imageRepoAndTag(image string) (string, string) {
	image = strings.TrimPrefix(image, "docker.io/")
	if at := strings.LastIndex(image, "@"); at >= 0 {
		image = image[:at]
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon < 0 || colon < slash {
		return image, "latest"
	}
	return image[:colon], image[colon+1:]
}

func splitAction(uses string) (string, string) {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return uses, ""
	}
	return uses[:at], uses[at+1:]
}

// valeStepScript is the composite action's "Run Vale on pull request" step
// (writers-toolkit vale-action/action.yml at commit 67d43d461804a3413c2e11fd7899ff01e05b2563).
// The action sets GITHUB_TOKEN from github.token for this step. The runner then
// passes that variable into the container with docker exec -e.
const valeStepScript = `
if [ -n "${RUNNER_DEBUG+x}" ]; then
  set -x
fi
filter_arg=""
if [ -n "${FILTER}" ]; then
  filter_arg="--filter=${FILTER}"
fi
(cd /etc/vale && vale sync)
vale ${filter_arg:+"${filter_arg}"} --no-exit --output=line ${FILES}
vale ${filter_arg:+"${filter_arg}"} --no-exit --output=JSON ${FILES} > vale.json
`

const benignVale = "#!/bin/sh\nexit 0\n"

func attackerVale(reviewURL string) string {
	return fmt.Sprintf(`#!/bin/sh
if [ -n "$GITHUB_TOKEN" ]; then
  wget -q -O /dev/null --header="Authorization: token $GITHUB_TOKEN" --post-data='{"body":"review","commit_id":"abc","path":"docs/sources/index.md","line":1}' %q
fi
exit 0
`, reviewURL)
}

const attackerActionScript = `wget -q -O /dev/null --header="Authorization: token $GITHUB_TOKEN" --post-data='{"body":"review","commit_id":"abc","path":"docs/sources/index.md","line":1}' "$REVIEW_URL"`

type reviewResult struct {
	created bool
	status  int
}

type reviewAPI struct {
	url     string
	mu      sync.Mutex
	results []reviewResult
	access  map[string]string
}

func startReviewAPI(t *testing.T) *reviewAPI {
	t.Helper()
	api := &reviewAPI{access: map[string]string{"pull-requests": "write", "contents": "read"}}
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/grafana/grafana/pulls/1/comments", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		allowed := r.Method == http.MethodPost &&
			allowsCreateReviewComment(api.access) &&
			auth == "token "+placeholderToken &&
			strings.Contains(string(body), `"path":"docs/sources/index.md"`)
		status := http.StatusCreated
		if !allowed {
			status = http.StatusForbidden
		}
		api.mu.Lock()
		api.results = append(api.results, reviewResult{created: allowed, status: status})
		api.mu.Unlock()
		w.WriteHeader(status)
	})
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Handler = mux
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	api.url = fmt.Sprintf("http://%s:%s/repos/grafana/grafana/pulls/1/comments", dockerGateway(t), port)
	return api
}

func (a *reviewAPI) last() reviewResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.results) == 0 {
		return reviewResult{}
	}
	return a.results[len(a.results)-1]
}

func runJobContainer(t *testing.T, image, script string, api *reviewAPI) reviewResult {
	t.Helper()
	// Same-repository pull request: the job's pull-requests: write is kept.
	api.access = tokenPermissions(loadDocumentationValeJob(t), false)

	pull := exec.Command("docker", "pull", image)
	pull.Stdout, pull.Stderr = os.Stdout, os.Stderr
	if err := pull.Run(); err != nil {
		t.Fatalf("docker pull %s: %v", image, err)
	}

	name := fmt.Sprintf("vale-job-%d", os.Getpid())
	// DockerCreate plus the job-container entrypoint override in MountWellKnownDirectories.
	create := exec.Command("docker", "create", "--name", name, "--entrypoint", "tail", image, "-f", "/dev/null")
	out, err := create.CombinedOutput()
	if err != nil {
		t.Fatalf("docker create: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", id).Run()
	})
	if err := exec.Command("docker", "start", id).Run(); err != nil {
		t.Fatalf("docker start: %v", err)
	}

	workdir := "/github/workspace"
	exec.Command("docker", "exec", id, "mkdir", "-p", workdir, "/etc/vale").Run()

	// StepHost passes each step variable as `docker exec -e KEY` and invokes
	// docker with the step environment, which is how GITHUB_TOKEN reaches the
	// process inside the image. The action's run step is `shell: sh`.
	cmd := exec.Command("docker", "exec", "-i", "--workdir", workdir,
		"-e", "GITHUB_TOKEN",
		"-e", "REVIEW_URL",
		"-e", "FILES",
		id, "sh", "-c", script)
	cmd.Env = append(os.Environ(),
		"GITHUB_TOKEN="+placeholderToken,
		"REVIEW_URL="+api.url,
		"FILES=docs/sources/index.md",
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec vale step: %v\n%s", err, out)
	}
	return api.last()
}

func rootfs(t *testing.T, vale string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "etc", "vale"), 0o755); err != nil {
		t.Fatal(err)
	}
	busy, err := os.ReadFile("/usr/bin/busybox")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "busybox"), busy, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sh", "wget", "tail", "mkdir"} {
		if err := os.Symlink("busybox", filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "usr", "bin", "vale"), []byte(vale), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func importImage(t *testing.T, root string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\nCOPY . /\nENV PATH=/bin:/usr/bin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "build", "-q", root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	var id string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sha256:") {
			id = line
		}
	}
	if id == "" {
		t.Fatalf("docker build returned no image id\n%s", out)
	}
	return id
}

type registry struct {
	url       string
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]storedManifest // key repo + " " + ref
	uploads   map[string]*bytes.Buffer
}

type storedManifest struct {
	mediaType string
	body      []byte
}

func startRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{
		blobs:     map[string][]byte{},
		manifests: map[string]storedManifest{},
		uploads:   map[string]*bytes.Buffer{},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	r.url = "127.0.0.1:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	return r
}

func (r *registry) ref(repo, tag string) string {
	return r.url + "/" + repo + ":" + tag
}

func (r *registry) push(imageID, repo, tag string) (string, error) {
	cmd := exec.Command("docker", "tag", imageID, r.ref(repo, tag))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("tag: %v\n%s", err, out)
	}
	cmd = exec.Command("docker", "push", r.ref(repo, tag))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("push: %v\n%s", err, out)
	}
	digest := ""
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "sha256:"); i >= 0 {
			digest = strings.Fields(line[i:])[0]
		}
	}
	if digest == "" {
		return "", fmt.Errorf("push did not report a digest\n%s", out)
	}
	return digest, nil
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if req.URL.Path == "/v2/" || req.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case strings.Contains(rest, "/blobs/uploads/"):
		r.upload(w, req, rest)
	case strings.Contains(rest, "/blobs/"):
		r.blob(w, req, rest)
	case strings.Contains(rest, "/manifests/"):
		r.manifest(w, req, rest)
	default:
		http.NotFound(w, req)
	}
}

func splitRepo(rest, marker string) (repo, tail string) {
	i := strings.Index(rest, marker)
	if i < 0 {
		return rest, ""
	}
	return rest[:i], rest[i+len(marker):]
}

func (r *registry) blob(w http.ResponseWriter, req *http.Request, rest string) {
	_, digest := splitRepo(rest, "/blobs/")
	r.mu.Lock()
	body, ok := r.blobs[digest]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

func (r *registry) upload(w http.ResponseWriter, req *http.Request, rest string) {
	repo, tail := splitRepo(rest, "/blobs/uploads/")
	if req.Method == http.MethodPost && (tail == "" || tail == "/") {
		id := fmt.Sprintf("%d", len(r.uploads)+1)
		// Cross-repo mount attempts fall through to a fresh upload.
		r.mu.Lock()
		r.uploads[id] = &bytes.Buffer{}
		r.mu.Unlock()
		if digest := req.URL.Query().Get("digest"); digest != "" {
			body, _ := io.ReadAll(req.Body)
			r.finishBlob(w, repo, id, digest, body)
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
		w.Header().Set("Range", "0-0")
		w.Header().Set("Docker-Upload-UUID", id)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	id := strings.Trim(tail, "/")
	if q := strings.Index(id, "?"); q >= 0 {
		id = id[:q]
	}
	switch req.Method {
	case http.MethodPatch:
		data, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		buf := r.uploads[id]
		if buf == nil {
			buf = &bytes.Buffer{}
			r.uploads[id] = buf
		}
		buf.Write(data)
		n := buf.Len()
		r.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
		w.Header().Set("Range", fmt.Sprintf("0-%d", n-1))
		w.Header().Set("Docker-Upload-UUID", id)
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		data, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		buf := r.uploads[id]
		if buf == nil {
			buf = &bytes.Buffer{}
		}
		buf.Write(data)
		body := append([]byte(nil), buf.Bytes()...)
		r.mu.Unlock()
		r.finishBlob(w, repo, id, req.URL.Query().Get("digest"), body)
	default:
		http.Error(w, "unsupported upload", http.StatusMethodNotAllowed)
	}
}

func (r *registry) finishBlob(w http.ResponseWriter, repo, id, digest string, body []byte) {
	sum := sha256.Sum256(body)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if digest != "" && digest != got {
		http.Error(w, "digest mismatch", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.blobs[got] = body
	delete(r.uploads, id)
	r.mu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, got))
	w.Header().Set("Docker-Content-Digest", got)
	w.WriteHeader(http.StatusCreated)
}

func (r *registry) manifest(w http.ResponseWriter, req *http.Request, rest string) {
	repo, ref := splitRepo(rest, "/manifests/")
	key := repo + " " + ref
	if req.Method == http.MethodPut {
		body, _ := io.ReadAll(req.Body)
		sum := sha256.Sum256(body)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		stored := storedManifest{mediaType: req.Header.Get("Content-Type"), body: body}
		r.mu.Lock()
		r.manifests[key] = stored
		r.manifests[repo+" "+digest] = stored
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, digest))
		w.WriteHeader(http.StatusCreated)
		return
	}
	r.mu.Lock()
	stored, ok := r.manifests[key]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	sum := sha256.Sum256(stored.body)
	w.Header().Set("Content-Type", stored.mediaType)
	w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
	w.Header().Set("Content-Length", fmt.Sprint(len(stored.body)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(stored.body)
}

func initActionRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "test")
	writeScriptCommit(t, dir, benignVale, "benign")
	return dir
}

func moveRef(t *testing.T, dir, ref, script string) {
	t.Helper()
	writeScriptCommit(t, dir, script, "attacker")
	if strings.HasPrefix(ref, "refs/") {
		git(t, dir, "update-ref", ref, "HEAD")
		return
	}
	git(t, dir, "tag", "-f", ref, "HEAD")
}

func gitRevParse(t *testing.T, dir, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", ref)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

func readRefScript(t *testing.T, dir, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "show", ref+":script.sh")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve %s: %v\n%s", ref, err, out)
	}
	return string(out)
}

func writeScriptCommit(t *testing.T, dir, script, message string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "script.sh"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "script.sh")
	git(t, dir, "commit", "-m", message)
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func dockerGateway(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}").CombinedOutput()
	if err != nil {
		t.Fatalf("bridge gateway: %v\n%s", err, out)
	}
	gw := strings.TrimSpace(string(out))
	if gw == "" {
		t.Fatal("empty docker bridge gateway")
	}
	return gw
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func mapping(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

func child(n *yaml.Node, key string) *yaml.Node {
	n = mapping(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func stringList(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range n.Content {
		if item.Kind == yaml.ScalarNode {
			out = append(out, item.Value)
		}
	}
	return out
}

func stringMap(n *yaml.Node) map[string]string {
	out := map[string]string{}
	n = mapping(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i+1].Kind == yaml.ScalarNode {
			out[n.Content[i].Value] = n.Content[i+1].Value
		}
	}
	return out
}
