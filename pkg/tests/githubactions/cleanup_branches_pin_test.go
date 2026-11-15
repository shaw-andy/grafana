package githubactions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/cleanup-branches-action.yml
var cleanupActionYML string

// These tests exercise .github/workflows/cleanup-branches.yml.
//
// The job grants contents: write and checks out actions by git ref. The runner
// asks the service to resolve the ref string from the workflow at job time
// (actions/runner v2.338.2 ActionManager.GetDownloadInfoAsync sends Ref through
// unchanged). A full commit SHA is content-addressed. A tag is a movable ref:
// git update-ref changes which commit it names, which is what
// GET /repos/grafana/shared-workflows/git/ref/tags/cleanup-branches/v0.2.1 reads.
//
// The workflow token is github.token (runner ExecutionContext sets that context
// from system.github.token). It is not exported as GITHUB_TOKEN — GitHubContext's
// environment allowlist omits "token" — but composite steps evaluate
// ${{ github.token }} into inputs and step env (ActionManifestManager.EvaluateDefaultInput,
// CompositeActionHandler). actions/checkout persists it as http.<origin>.extraheader
// "AUTHORIZATION: basic" base64("x-access-token:"+token) when persist-credentials
// is true, which is that action's default. Later steps' git push therefore
// authenticate as the workflow token.
//
// git http-backend (git 2.43.0) is what serves the fixture. Anonymous clients may
// fetch. git-receive-pack requires the workflow token, matching the authenticated
// write / anonymous read example in Documentation/git-http-backend.txt. A
// pre-receive hook rejects updates to refs/heads/main. Other branches accept
// deletes from that token only, which is the contents: write scope this workflow
// grants and the permission cleanup-branches' action.yml says delete needs.
//
// The stand-in gh(1) answers the two calls in that action: open pull-request
// heads and protected branch names. Protected names are main, the same ref the
// hook rejects.

const (
	workflowToken = "workflow-token-placeholder"
	attackerToken = "attacker-token-placeholder"

	productRepo = "grafana/grafana"

	// Branches the legitimate cleanup action must not delete.
	youngBranch     = "release/12.0"
	openPRBranch    = "feature/open-pr"
	protectedBranch = "main"
	// Old orphan the legitimate action does delete. The assertions below do not
	// require it to survive.
	oldOrphan = "old-orphan"
)

func TestCleanupBranchesRetagCannotDeleteUnprotectedBranches(t *testing.T) {
	root := moduleRoot(t)
	wfPath := filepath.Join(root, ".github", "workflows", "cleanup-branches.yml")
	info, err := os.Stat(wfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatalf("%s is a directory", wfPath)
	}
	wf := loadWorkflow(t, wfPath)
	if !workflowRunsOnItsOwn(wf.raw) {
		return
	}
	job, ok := wf.jobs["cleanup-branches"]
	if !ok {
		return
	}
	write := job.contents == "write"
	var uses []workflowStep
	for _, step := range job.steps {
		if step.uses != "" {
			uses = append(uses, step)
		}
	}
	if len(uses) == 0 {
		return
	}

	for _, attacked := range uses {
		attacked := attacked
		t.Run(strings.ReplaceAll(attacked.uses, "/", "_"), func(t *testing.T) {
			srv := newProductServer(t, write)
			defer srv.close()

			if err := deleteRemoteBranch(t, srv, attackerToken, youngBranch); err == nil {
				t.Fatal("attacker credential deleted a branch; the fixture accepted a token other than the workflow token")
			}
			if !srv.hasBranch(youngBranch) || !srv.hasBranch(openPRBranch) || !srv.hasBranch(protectedBranch) {
				t.Fatalf("attacker credential changed refs: %s", srv.branches())
			}

			err := srv.runJob(t, job.steps, attacked.uses)
			missing := srv.missing([]string{protectedBranch, youngBranch, openPRBranch})
			if len(missing) > 0 {
				t.Errorf("uses %s ref is resolved when the job runs; after that ref was moved, the job deleted %v with the workflow token (contents: %q). Pin every action in this job to a full commit SHA, or stop granting contents: write.\nremaining refs: %s\njob log:\n%s",
					attacked.uses, missing, job.contents, srv.branches(), srv.log.String())
				return
			}
			// A contents: write job whose actions are still tags must actually
			// perform the delete. An error that leaves the branches in place is a
			// broken fixture, not a fix. Dropping contents: write makes the push
			// fail and the branches remain; that is a fix.
			if err != nil && write {
				t.Fatalf("job failed without deleting the branches: %v\n%s", err, srv.log.String())
			}
		})
	}
}

type workflowFile struct {
	raw  map[string]interface{}
	jobs map[string]workflowJob
}

type workflowJob struct {
	contents string
	steps    []workflowStep
}

type workflowStep struct {
	uses string
	with map[string]interface{}
}

func loadWorkflow(t *testing.T, path string) workflowFile {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	out := workflowFile{raw: raw, jobs: map[string]workflowJob{}}
	jobs, _ := raw["jobs"].(map[string]interface{})
	for name, value := range jobs {
		jobMap, _ := value.(map[string]interface{})
		job := workflowJob{}
		if perms, ok := jobMap["permissions"].(map[string]interface{}); ok {
			if c, ok := perms["contents"].(string); ok {
				job.contents = c
			}
		}
		steps, _ := jobMap["steps"].([]interface{})
		for _, stepValue := range steps {
			stepMap, _ := stepValue.(map[string]interface{})
			step := workflowStep{uses: stringify(stepMap["uses"])}
			if with, ok := stepMap["with"].(map[string]interface{}); ok {
				step.with = with
			}
			job.steps = append(job.steps, step)
		}
		out.jobs[name] = job
	}
	return out
}

func workflowRunsOnItsOwn(raw map[string]interface{}) bool {
	on, ok := raw["on"].(map[string]interface{})
	if !ok {
		return false
	}
	if _, ok := on["schedule"]; ok {
		return true
	}
	if _, ok := on["workflow_dispatch"]; ok {
		return true
	}
	return false
}

type productServer struct {
	t         *testing.T
	write     bool
	server    *httptest.Server
	bare      string
	root      string
	gitConfig string
	home      string
	log       bytes.Buffer
}

func newProductServer(t *testing.T, write bool) *productServer {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	gitConfig := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(gitConfig, []byte("[init]\n\tdefaultBranch = main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(root, "grafana", "grafana")
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := &productServer{t: t, write: write, bare: bare, root: root, gitConfig: gitConfig, home: home}
	srv.git(bare, "init", "--bare")
	srv.git(bare, "config", "http.receivepack", "true")
	srv.seed()
	hook := filepath.Join(bare, "hooks", "pre-receive")
	if err := os.WriteFile(hook, []byte(preReceiveHook), 0o755); err != nil {
		t.Fatal(err)
	}
	srv.server = httptest.NewServer(http.HandlerFunc(srv.handle))
	return srv
}

func (s *productServer) close() { s.server.Close() }

func (s *productServer) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if isReceivePack(r) {
		if !s.write || !workflowCredential(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Git Access"`)
			http.Error(w, "write access denied", http.StatusForbidden)
			return
		}
	}
	raw, err := runGitHTTPBackend(r, body, s.root)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeCGI(w, raw)
}

func isReceivePack(r *http.Request) bool {
	if strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
		return true
	}
	return r.URL.Query().Get("service") == "git-receive-pack"
}

func workflowCredential(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == "x-access-token" && pass == workflowToken
}

func runGitHTTPBackend(r *http.Request, body []byte, projectRoot string) ([]byte, error) {
	cmd := exec.Command("/usr/lib/git-core/git-http-backend")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_PROJECT_ROOT=" + projectRoot,
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD=" + r.Method,
		"QUERY_STRING=" + r.URL.RawQuery,
		"PATH_INFO=" + r.URL.Path,
		"SERVER_PROTOCOL=HTTP/1.1",
		"CONTENT_TYPE=" + r.Header.Get("Content-Type"),
		"CONTENT_LENGTH=" + strconv.Itoa(len(body)),
		"REMOTE_ADDR=127.0.0.1",
		"REMOTE_USER=workflow",
	}
	if proto := r.Header.Get("Git-Protocol"); proto != "" {
		cmd.Env = append(cmd.Env, "GIT_PROTOCOL="+proto)
	}
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git http-backend: %w (%s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func writeCGI(w http.ResponseWriter, raw []byte) {
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	n := 4
	if sep < 0 {
		sep = bytes.Index(raw, []byte("\n\n"))
		n = 2
	}
	header, body := raw, []byte(nil)
	if sep >= 0 {
		header, body = raw[:sep], raw[sep+n:]
	}
	status := 200
	for _, line := range bytes.Split(header, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		key, val, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		name := string(bytes.TrimSpace(key))
		value := string(bytes.TrimSpace(val))
		if strings.EqualFold(name, "Status") {
			fmt.Sscanf(value, "%d", &status)
			continue
		}
		w.Header().Add(name, value)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

const preReceiveHook = `#!/bin/sh
while read old new ref; do
  case "$ref" in
    refs/heads/main)
      echo "protected: $ref" >&2
      exit 1
      ;;
  esac
done
exit 0
`

func (s *productServer) seed() {
	work := filepath.Join(s.root, "seed")
	s.git(work, "init", "-b", "main")
	s.commitFile(work, "README", "main", "initial", "")
	s.git(work, "checkout", "-b", youngBranch)
	s.commitFile(work, "release.txt", "young", "release branch", "")
	s.git(work, "checkout", "main")
	s.git(work, "checkout", "-b", openPRBranch)
	s.commitFile(work, "pr.txt", "open pr", "open pull request branch", "2020-01-15T00:00:00Z")
	s.git(work, "checkout", "main")
	s.git(work, "checkout", "-b", oldOrphan)
	s.commitFile(work, "old.txt", "old", "orphaned branch", "2020-01-15T00:00:00Z")
	s.git(work, "checkout", "main")
	s.git(work, "remote", "add", "origin", s.bare)
	s.git(work, "push", "origin", "main", youngBranch, openPRBranch, oldOrphan)
}

func (s *productServer) commitFile(dir, name, content, message, date string) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		s.t.Fatal(err)
	}
	s.git(dir, "add", name)
	args := []string{"commit", "-m", message}
	env := s.baseEnv()
	if date != "" {
		env = append(env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	}
	if _, err := s.gitEnv(dir, env, args...); err != nil {
		s.t.Fatal(err)
	}
}

func (s *productServer) hasBranch(name string) bool {
	out, err := s.gitOutput(s.bare, "show-ref", "--verify", "--quiet", "refs/heads/"+name)
	_ = out
	return err == nil
}

func (s *productServer) missing(names []string) []string {
	var gone []string
	for _, name := range names {
		if !s.hasBranch(name) {
			gone = append(gone, name)
		}
	}
	return gone
}

func (s *productServer) branches() string {
	out, err := s.gitOutput(s.bare, "show-ref")
	if err != nil {
		return err.Error()
	}
	return out
}

func (s *productServer) runJob(t *testing.T, steps []workflowStep, attackedUses string) error {
	t.Helper()
	workspace := filepath.Join(s.root, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return err
	}
	ghDir := filepath.Join(s.root, "bin")
	if err := os.MkdirAll(ghDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ghDir, "gh"), []byte(ghStub), 0o755); err != nil {
		return err
	}
	serverURL := s.server.URL
	github := map[string]string{
		"github.token":                           workflowToken,
		"github.repository":                      productRepo,
		"github.server_url":                      serverURL,
		"github.event.repository.default_branch": "main",
		"github.workspace":                       workspace,
	}
	for _, step := range steps {
		if step.uses == "" {
			continue
		}
		ownerRepo, actionPath, ref, err := parseUses(step.uses)
		if err != nil {
			return err
		}
		var tree string
		if fullSHA.MatchString(ref) {
			tree, err = downloadAction(t, ownerRepo, actionPath, ref)
		} else {
			tree, err = s.localAction(t, ownerRepo, actionPath, ref, step.uses == attackedUses)
		}
		if err != nil {
			return err
		}
		if err := s.executeAction(t, tree, actionPath, step, github, workspace, ghDir); err != nil {
			return fmt.Errorf("%s: %w", step.uses, err)
		}
	}
	return nil
}

var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func parseUses(uses string) (ownerRepo, actionPath, ref string, err error) {
	at := strings.LastIndex(uses, "@")
	if at <= 0 {
		return "", "", "", fmt.Errorf("uses %q has no ref", uses)
	}
	left, ref := uses[:at], uses[at+1:]
	parts := strings.Split(left, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("uses %q has no owner/repo", uses)
	}
	ownerRepo = parts[0] + "/" + parts[1]
	if len(parts) > 2 {
		actionPath = strings.Join(parts[2:], "/")
	}
	return ownerRepo, actionPath, ref, nil
}

func (s *productServer) localAction(t *testing.T, ownerRepo, actionPath, ref string, attack bool) (string, error) {
	t.Helper()
	repo := filepath.Join(s.root, "actions", strings.ReplaceAll(ownerRepo, "/", "_"))
	if _, err := os.Stat(repo); err != nil {
		s.git(repo, "init", "-b", "main")
		benign := benignAction(ownerRepo, actionPath)
		if err := writeAction(repo, actionPath, benign); err != nil {
			return "", err
		}
		s.git(repo, "add", ".")
		s.git(repo, "commit", "-m", "publish action")
		s.git(repo, "update-ref", "refs/tags/"+ref, "HEAD")
	}
	if attack {
		if err := writeAction(repo, actionPath, maliciousAction); err != nil {
			return "", err
		}
		s.git(repo, "add", ".")
		s.git(repo, "commit", "-m", "move tag")
		s.git(repo, "update-ref", "refs/tags/"+ref, "HEAD")
	}
	sha, err := s.gitOutput(repo, "rev-parse", "refs/tags/"+ref)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(s.root, "materialized", strings.ReplaceAll(ownerRepo, "/", "_")+"-"+sha[:12])
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	archive, err := s.gitRaw(repo, "archive", sha)
	if err != nil {
		return "", err
	}
	if err := untar(archive, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func benignAction(ownerRepo, actionPath string) string {
	if ownerRepo == "grafana/shared-workflows" && actionPath == "actions/cleanup-branches" {
		return cleanupActionYML
	}
	return checkoutStandIn
}

func writeAction(repo, actionPath, yml string) error {
	dir := filepath.Join(repo, actionPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(yml), 0o644); err != nil {
		return err
	}
	if strings.Contains(yml, "using: node") {
		return os.WriteFile(filepath.Join(dir, "index.js"), []byte("// credential setup is performed by the test harness\n"), 0o644)
	}
	return nil
}

func downloadAction(t *testing.T, ownerRepo, actionPath, sha string) (string, error) {
	t.Helper()
	url := "https://codeload.github.com/" + ownerRepo + "/tar.gz/" + sha
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(t.TempDir(), "action")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	if err := untar(gz, dest); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", fmt.Errorf("tarball for %s@%s has %d top-level entries", ownerRepo, sha, len(entries))
	}
	return filepath.Join(dest, entries[0].Name()), nil
}

func (s *productServer) executeAction(t *testing.T, tree, actionPath string, step workflowStep, github map[string]string, workspace, ghDir string) error {
	t.Helper()
	manifestPath := filepath.Join(tree, actionPath, "action.yml")
	if _, err := os.Stat(manifestPath); err != nil {
		alt := filepath.Join(tree, actionPath, "action.yaml")
		if _, err2 := os.Stat(alt); err2 != nil {
			return fmt.Errorf("no action.yml under %s", actionPath)
		}
		manifestPath = alt
	}
	manifest, err := parseAction(manifestPath)
	if err != nil {
		return err
	}
	inputs := resolveInputs(manifest, step.with, github)
	switch {
	case strings.HasPrefix(strings.ToLower(manifest.Runs.Using), "node"):
		return s.runNodeCheckout(workspace, inputs, github)
	case strings.EqualFold(manifest.Runs.Using, "composite"):
		return s.runComposite(manifest, inputs, github, workspace, ghDir)
	default:
		return fmt.Errorf("unsupported runs.using %q", manifest.Runs.Using)
	}
}

func (s *productServer) runNodeCheckout(workspace string, inputs, github map[string]string) error {
	repo := inputs["repository"]
	if repo == "" {
		repo = github["github.repository"]
	}
	token := inputs["token"]
	if _, err := os.Stat(filepath.Join(workspace, ".git")); err != nil {
		parent := filepath.Dir(workspace)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		if _, err := s.gitOutput(parent, "clone", github["github.server_url"]+"/"+repo, workspace); err != nil {
			return err
		}
	}
	// actions/checkout action.yml defaults persist-credentials to true and token
	// to ${{ github.token }}. git-auth-helper.ts writes the basic extraheader
	// into the local config when that input is true.
	if strings.EqualFold(inputs["persist-credentials"], "true") && token != "" {
		key := "http." + github["github.server_url"] + "/.extraheader"
		if _, err := s.gitOutput(workspace, "config", "--local", key, basicHeader(token)); err != nil {
			return err
		}
	}
	return nil
}

func basicHeader(token string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "AUTHORIZATION: basic " + encoded
}

func (s *productServer) runComposite(manifest actionManifest, inputs, github map[string]string, workspace, ghDir string) error {
	for i, step := range manifest.Runs.Steps {
		if step.If != "" && evalExpr(step.If, github, inputs) != "true" {
			fmt.Fprintf(&s.log, "skip step %d %q\n", i, step.Name)
			continue
		}
		env := s.baseEnv()
		env = append(env,
			"PATH="+ghDir+":"+os.Getenv("PATH"),
			"GITHUB_REPOSITORY="+github["github.repository"],
			"GITHUB_SERVER_URL="+github["github.server_url"],
			"GITHUB_WORKSPACE="+workspace,
		)
		for key, value := range step.Env {
			env = append(env, key+"="+evalExpr(value, github, inputs))
		}
		script := filepath.Join(s.root, fmt.Sprintf("step-%d.sh", i))
		if err := os.WriteFile(script, []byte(step.Run), 0o755); err != nil {
			return err
		}
		cmd := exec.Command("bash", script)
		cmd.Dir = workspace
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		fmt.Fprintf(&s.log, "step %d %q exit=%v\n%s\n", i, step.Name, err, out)
		if err != nil {
			return fmt.Errorf("step %q: %w\n%s", step.Name, err, out)
		}
	}
	return nil
}

type actionManifest struct {
	Inputs map[string]actionInput `yaml:"inputs"`
	Runs   struct {
		Using string       `yaml:"using"`
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

type actionInput struct {
	Default interface{} `yaml:"default"`
}

type actionStep struct {
	Name  string            `yaml:"name"`
	Shell string            `yaml:"shell"`
	If    string            `yaml:"if"`
	Env   map[string]string `yaml:"env"`
	Run   string            `yaml:"run"`
}

func parseAction(path string) (actionManifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return actionManifest{}, err
	}
	var manifest actionManifest
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return actionManifest{}, err
	}
	return manifest, nil
}

func resolveInputs(manifest actionManifest, with map[string]interface{}, github map[string]string) map[string]string {
	inputs := map[string]string{}
	for name, input := range manifest.Inputs {
		if input.Default != nil {
			inputs[name] = evalExpr(stringify(input.Default), github, nil)
		}
	}
	for name, value := range with {
		inputs[name] = stringify(value)
	}
	return inputs
}

var exprPattern = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

func evalExpr(s string, github, inputs map[string]string) string {
	return exprPattern.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(match[3 : len(match)-2])
		if left, right, ok := strings.Cut(inner, "=="); ok {
			lhs := lookupAtom(strings.TrimSpace(left), github, inputs)
			rhs := strings.Trim(strings.TrimSpace(right), `"'`)
			if lhs == rhs {
				return "true"
			}
			return "false"
		}
		return lookupAtom(inner, github, inputs)
	})
}

func lookupAtom(atom string, github, inputs map[string]string) string {
	if value, ok := github[atom]; ok {
		return value
	}
	if strings.HasPrefix(atom, "inputs.") {
		return inputs[strings.TrimPrefix(atom, "inputs.")]
	}
	return ""
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

func deleteRemoteBranch(t *testing.T, s *productServer, token, branch string) error {
	t.Helper()
	dir := filepath.Join(s.root, "attacker")
	s.git(dir, "init", "-b", "main")
	s.git(dir, "remote", "add", "origin", s.server.URL+"/"+productRepo)
	key := "http." + s.server.URL + "/.extraheader"
	s.git(dir, "config", "--local", key, basicHeader(token))
	_, err := s.gitOutput(dir, "push", "origin", "--delete", branch)
	return err
}

func (s *productServer) baseEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + s.home,
		"GIT_CONFIG_GLOBAL=" + s.gitConfig,
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Cleanup Pin Test",
		"GIT_AUTHOR_EMAIL=cleanup-pin-test@example.com",
		"GIT_COMMITTER_NAME=Cleanup Pin Test",
		"GIT_COMMITTER_EMAIL=cleanup-pin-test@example.com",
		"LC_ALL=C",
	}
}

func (s *productServer) git(dir string, args ...string) {
	s.t.Helper()
	if _, err := s.gitOutput(dir, args...); err != nil {
		s.t.Fatal(err)
	}
}

func (s *productServer) gitOutput(dir string, args ...string) (string, error) {
	return s.gitEnv(dir, s.baseEnv(), args...)
}

func (s *productServer) gitEnv(dir string, env []string, args ...string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
		return "", err
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s (%s): %w\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *productServer) gitRaw(dir string, args ...string) (io.Reader, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = s.baseEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return &stdout, nil
}

func untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) && target != filepath.Clean(dest) {
			return fmt.Errorf("tar path escapes dest: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
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

const ghStub = `#!/bin/bash
joined="$*"
case "$joined" in
  *"pr list"*)
    printf '%s\n' '[{"headRefName":"feature/open-pr"}]'
    ;;
  *"api"*)
    printf '%s\n' '[{"name":"main"}]'
    ;;
  *)
    echo "unhandled gh invocation: $joined" >&2
    exit 1
    ;;
esac
`

const checkoutStandIn = `name: Checkout
description: Credential persistence from actions/checkout git-auth-helper.ts
inputs:
  repository:
    default: ${{ github.repository }}
  token:
    default: ${{ github.token }}
  persist-credentials:
    default: "true"
runs:
  using: node20
  main: index.js
`

const maliciousAction = `name: retagged
runs:
  using: composite
  steps:
    - name: delete refs with the workflow token
      shell: bash
      env:
        WORKFLOW_TOKEN: ${{ github.token }}
      run: |
        set -eu
        if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
          git init -b main
          git remote add origin "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"
        fi
        basic=$(printf 'x-access-token:%s' "$WORKFLOW_TOKEN" | base64 -w0)
        git config --local "http.${GITHUB_SERVER_URL}/.extraheader" "AUTHORIZATION: basic ${basic}"
        mapfile -t refs < <(git ls-remote --heads origin | awk '{print $2}')
        for ref in "${refs[@]}"; do
          name=${ref#refs/heads/}
          if [ "$name" = "main" ]; then
            git push origin --delete "$name" || true
          else
            git push origin --delete "$name"
          fi
        done
`
