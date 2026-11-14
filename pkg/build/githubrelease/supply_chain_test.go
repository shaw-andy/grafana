package githubrelease

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests exercise the release workflows as they are run:
// workflow_dispatch of "Create or update GitHub release", and the
// create_github_release job in the post-release workflow.
//
// A uses ref that is not a full commit SHA is resolved at job start to
// whatever object that ref currently names. The tests point that ref at
// a different commit and run the steps that commit contains. The job
// token is the one declared by the job's permissions block. contents: write
// is allowed to create and update releases. id-token: write makes the
// OIDC request URL available to every run step.
//
// The assertions fail while those refs still move. They pass when the
// release-publishing job no longer grants id-token: write and every
// uses that runs with contents: write or id-token: write is a 40-digit
// commit SHA whose tree does not contain the later commit.

const (
	jobToken     = "ghs_test_placeholder"
	oidcRequest  = "oidc_request_placeholder"
	oidcJWT      = "oidc-jwt-placeholder"
	seedBody     = "published-changelog"
	attackerBody = "attacker-replaced-release"
	attackMarker = "ATTACKER_SUPPLY_CHAIN"
	releaseTag   = "v10.0.0"
)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestGitHubReleaseSupplyChain(t *testing.T) {
	root := repoRoot(t)
	in := releaseInputs{version: "10.0.0", latest: "1", dryRun: false, event: "workflow_dispatch", repository: "grafana/grafana"}

	t.Run("dispatch", func(t *testing.T) {
		wf := readFile(t, filepath.Join(root, ".github", "workflows", "github-release.yml"))
		runWorkflow(t, root, wf, nil, in)
	})

	t.Run("post_release_calls_github_release", func(t *testing.T) {
		comms := readFile(t, filepath.Join(root, ".github", "workflows", "release-comms.yml"))
		// Only the job that publishes the GitHub release. Other post-release
		// jobs also call reusable workflows at @main with id-token: write
		// (create-next-release-branch.yml, create-security-branch.yml,
		// migrate-prs.yml). Those are not this publish path and are not run here.
		runNamedJob(t, root, comms, "create_github_release", nil, in)
	})
}

type releaseInputs struct {
	version    string
	latest     string
	dryRun     bool
	event      string
	repository string
}

type workflowFile struct {
	Jobs map[string]jobYAML `yaml:"jobs"`
}

type jobYAML struct {
	Permissions map[string]string `yaml:"permissions"`
	Uses        string            `yaml:"uses"`
	With        map[string]any    `yaml:"with"`
	If          string            `yaml:"if"`
	Needs       yaml.Node         `yaml:"needs"`
	Steps       []stepYAML        `yaml:"steps"`
}

type stepYAML struct {
	Uses  string            `yaml:"uses"`
	With  map[string]any    `yaml:"with"`
	Env   map[string]string `yaml:"env"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
}

type actionFile struct {
	Runs struct {
		Using string     `yaml:"using"`
		Steps []stepYAML `yaml:"steps"`
	} `yaml:"runs"`
}

type releaseAPI struct {
	server *httptest.Server
	perms  map[string]string
	body   string
	id     int64
	oidc   bool
}

func newReleaseAPI(t *testing.T) *releaseAPI {
	t.Helper()
	api := &releaseAPI{body: seedBody, id: 1, perms: map[string]string{}}
	api.server = httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	return api
}

func (a *releaseAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oidc/token" {
		if !bearer(r, oidcRequest) || a.perms["id-token"] != "write" {
			http.Error(w, "oidc forbidden", http.StatusForbidden)
			return
		}
		a.oidc = true
		fmt.Fprint(w, oidcJWT)
		return
	}
	if !bearer(r, jobToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repos/grafana/grafana/releases/tags/"+releaseTag:
		if !contentsAtLeast(a.perms, "read") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeRelease(w, a)
	case r.Method == http.MethodPost && r.URL.Path == "/repos/grafana/grafana/releases":
		if !contentsAtLeast(a.perms, "write") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Body != "" {
			a.body = req.Body
		}
		writeRelease(w, a)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/grafana/grafana/releases/"):
		if !contentsAtLeast(a.perms, "write") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Body != "" {
			a.body = req.Body
		}
		writeRelease(w, a)
	default:
		http.NotFound(w, r)
	}
}

func writeRelease(w http.ResponseWriter, a *releaseAPI) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":       a.id,
		"tag_name": releaseTag,
		"body":     a.body,
	})
}

func bearer(r *http.Request, token string) bool {
	return r.Header.Get("Authorization") == "Bearer "+token
}

func contentsAtLeast(perms map[string]string, want string) bool {
	rank := map[string]int{"": 0, "none": 0, "read": 1, "write": 2}
	return rank[perms["contents"]] >= rank[want]
}

func runWorkflow(t *testing.T, root, content string, callerMax map[string]string, in releaseInputs) {
	t.Helper()
	var wf workflowFile
	if err := yaml.Unmarshal([]byte(content), &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	api := newReleaseAPI(t)
	for _, name := range orderJobs(t, wf.Jobs) {
		runJob(t, root, name, wf.Jobs[name], callerMax, in, api)
	}
	assertReleaseUntouched(t, api)
}

func runNamedJob(t *testing.T, root, content, jobName string, callerMax map[string]string, in releaseInputs) {
	t.Helper()
	var wf workflowFile
	if err := yaml.Unmarshal([]byte(content), &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	job, ok := wf.Jobs[jobName]
	if !ok {
		t.Fatalf("workflow has no %s job", jobName)
	}
	api := newReleaseAPI(t)
	runJob(t, root, jobName, job, callerMax, in, api)
	assertReleaseUntouched(t, api)
}

func assertReleaseUntouched(t *testing.T, api *releaseAPI) {
	t.Helper()
	if api.body == attackerBody {
		t.Errorf("release %s body is %q after the job; a moved uses ref ran with the contents write token", releaseTag, api.body)
	}
	if api.oidc {
		t.Errorf("a step obtained an OIDC token from the job's id-token permission")
	}
}

func runJob(t *testing.T, root, name string, job jobYAML, callerMax map[string]string, in releaseInputs, api *releaseAPI) {
	t.Helper()
	if !jobRuns(job.If, in) {
		return
	}
	perms := effectivePerms(job.Permissions)
	if callerMax != nil && exceeds(perms, callerMax) {
		// The called workflow is rejected and its steps do not run.
		return
	}
	api.perms = perms
	// A reusable-workflow caller has no steps of its own; its permissions are
	// only the maximum the called workflow may request. A job that runs steps
	// and grants both contents write and id-token write exposes the OIDC
	// request to those steps.
	if job.Uses == "" && perms["contents"] == "write" && perms["id-token"] == "write" {
		if requestOIDC(api) != http.StatusOK {
			t.Fatalf("job %s grants id-token: write but the OIDC endpoint refused the step", name)
		}
	}
	if job.Uses != "" {
		inner := resolveUses(t, root, job.Uses, perms, true)
		runWorkflow(t, root, inner, perms, in)
		return
	}
	for _, step := range job.Steps {
		runStep(t, root, step, perms, in, api)
	}
}

func runStep(t *testing.T, root string, step stepYAML, perms map[string]string, in releaseInputs, api *releaseAPI) {
	t.Helper()
	if step.Uses != "" {
		if strings.HasPrefix(step.Uses, "./") {
			return
		}
		body := resolveUses(t, root, step.Uses, perms, false)
		runAction(t, body, step.With, perms, in, api)
		return
	}
	if step.Run != "" {
		runScript(t, step.Run, step.Env, nil, perms, in, api)
	}
}

func runAction(t *testing.T, content string, with map[string]any, perms map[string]string, in releaseInputs, api *releaseAPI) {
	t.Helper()
	var action actionFile
	if err := yaml.Unmarshal([]byte(content), &action); err != nil {
		t.Fatalf("parse action: %v\n%s", err, content)
	}
	// JavaScript and Docker actions do not use the composite step list. A
	// full SHA names one immutable tree, so there is no later commit to run.
	if action.Runs.Using != "composite" {
		if strings.Contains(content, attackMarker) {
			t.Fatalf("non-composite action contains the attacker commit")
		}
		return
	}
	inputs := evalMap(with, in, api)
	for _, step := range action.Runs.Steps {
		if step.Uses != "" {
			if strings.HasPrefix(step.Uses, "./") || fullSHA.MatchString(usesRef(step.Uses)) {
				continue
			}
			body := resolveUses(t, rootFromTest(t), step.Uses, perms, false)
			runAction(t, body, step.With, perms, in, api)
			continue
		}
		runScript(t, step.Run, step.Env, inputs, perms, in, api)
	}
}

func runScript(t *testing.T, script string, env map[string]string, inputs map[string]string, perms map[string]string, in releaseInputs, api *releaseAPI) {
	t.Helper()
	script = subst(script, inputs, in, api)
	if !strings.Contains(script, attackMarker) {
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Dir = dir
	cmd.Env = scriptEnv(env, inputs, perms, in, api)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attack step failed: %v\n%s", err, out)
	}
}

func scriptEnv(env map[string]string, inputs map[string]string, perms map[string]string, in releaseInputs, api *releaseAPI) []string {
	got := append([]string{}, os.Environ()...)
	got = append(got,
		"GITHUB_API="+api.server.URL,
		"GITHUB_REPOSITORY="+in.repository,
	)
	for k, v := range env {
		got = append(got, k+"="+subst(v, inputs, in, api))
	}
	// actions/runner ScriptHandler sets these when the job connection carries GenerateIdTokenUrl.
	// The OIDC provider creates a token only when the job permissions include id-token: write.
	if perms["id-token"] == "write" {
		got = append(got,
			"ACTIONS_ID_TOKEN_REQUEST_URL="+api.server.URL+"/oidc/token",
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+oidcRequest,
		)
	}
	return got
}

func requestOIDC(api *releaseAPI) int {
	req, err := http.NewRequest(http.MethodGet, api.server.URL+"/oidc/token", nil)
	if err != nil {
		return http.StatusInternalServerError
	}
	req.Header.Set("Authorization", "Bearer "+oidcRequest)
	resp, err := api.server.Client().Do(req)
	if err != nil {
		return http.StatusInternalServerError
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func resolveUses(t *testing.T, root, uses string, perms map[string]string, workflow bool) string {
	t.Helper()
	owner, repo, path, ref, err := parseUses(uses)
	if err != nil {
		t.Fatal(err)
	}
	if fullSHA.MatchString(ref) {
		file := immutableFile(t, root, owner, repo, ref, path, workflow)
		if strings.Contains(file, attackMarker) {
			t.Fatalf("pinned SHA %s still contains the attacker commit", ref)
		}
		return file
	}
	// Branch and tag names are read again at job start. commitMovable moves
	// the ref, then checks it out, which is the lookup the runner asks the
	// service to do for a non-SHA ref.
	return commitMovable(t, ref, path, workflow, perms)
}

func commitMovable(t *testing.T, ref, path string, workflow bool, perms map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	filePath := materializePath(path, workflow)
	body := attackerYAML(workflow, perms)
	full := filepath.Join(dir, filePath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-m", "attacker")
	if ref != "main" {
		git(t, dir, "branch", "-f", ref, "HEAD")
		git(t, dir, "tag", "-f", ref, "HEAD")
	}
	return git(t, dir, "show", ref+":"+filePath)
}

func immutableFile(t *testing.T, root, owner, repo, sha, path string, workflow bool) string {
	t.Helper()
	var lastErr error
	for _, filePath := range candidatePaths(path, workflow) {
		var out []byte
		var err error
		if owner == "grafana" && repo == "grafana" {
			if _, statErr := exec.Command("git", "-C", root, "cat-file", "-e", sha+"^{commit}").Output(); statErr != nil {
				t.Fatalf("uses pin %s is not a commit in this repository", sha)
			}
			out, err = exec.Command("git", "-C", root, "show", sha+":"+filePath).Output()
		} else {
			out, err = gitShowRemote(t, owner, repo, sha, filePath)
		}
		if err == nil {
			return string(out)
		}
		lastErr = err
	}
	t.Fatalf("pinned %s/%s@%s: %v", owner, repo, sha, lastErr)
	return ""
}

func gitShowRemote(t *testing.T, owner, repo, sha, file string) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init")
	git(t, dir, "remote", "add", "origin", "https://github.com/"+owner+"/"+repo+".git")
	fetch := exec.Command("git", "fetch", "--depth", "1", "origin", sha)
	fetch.Dir = dir
	fetch.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := fetch.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("fetch %s/%s %s: %v\n%s", owner, repo, sha, err, out)
	}
	show := exec.Command("git", "show", sha+":"+file)
	show.Dir = dir
	out, err := show.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func candidatePaths(path string, workflow bool) []string {
	if workflow || strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		if path == "" {
			return []string{"action.yml", "action.yaml"}
		}
		return []string{path}
	}
	if path == "" {
		return []string{"action.yml", "action.yaml"}
	}
	return []string{path + "/action.yml", path + "/action.yaml"}
}

func materializePath(path string, workflow bool) string {
	return candidatePaths(path, workflow)[0]
}

func attackerYAML(workflow bool, perms map[string]string) string {
	contents := perms["contents"]
	if contents == "" {
		contents = "none"
	}
	idToken := perms["id-token"]
	if idToken == "" {
		idToken = "none"
	}
	tokenExpr := "${{ inputs.token }}"
	if workflow {
		tokenExpr = "${{ secrets.GITHUB_TOKEN }}"
	}
	step := map[string]any{
		"shell": "bash",
		"env":   map[string]string{"GITHUB_TOKEN": tokenExpr},
		"run":   attackScript(),
	}
	if workflow {
		doc := map[string]any{
			"name":        "attacker",
			"permissions": map[string]string{},
			"jobs": map[string]any{
				"main": map[string]any{
					"permissions": map[string]string{"contents": contents, "id-token": idToken},
					"runs-on":     "ubuntu-latest",
					"steps":       []any{step},
				},
			},
		}
		out, err := yaml.Marshal(doc)
		if err != nil {
			panic(err)
		}
		return string(out)
	}
	doc := map[string]any{
		"name": "attacker",
		"inputs": map[string]any{
			"token": map[string]any{"required": false},
		},
		"runs": map[string]any{
			"using": "composite",
			"steps": []any{step},
		},
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func attackScript() string {
	return attackMarker + "\n" + `python3 - <<'PY'
import json, os, urllib.request, urllib.error
api = os.environ["GITHUB_API"]
token = os.environ.get("GITHUB_TOKEN", "")

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(api + path, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

payload = {"tag_name": "` + releaseTag + `", "name": "10.0.0", "body": "` + attackerBody + `", "make_latest": "true"}
status, raw = call("GET", "/repos/grafana/grafana/releases/tags/` + releaseTag + `")
if status == 200:
    rel = json.loads(raw)
    call("PATCH", "/repos/grafana/grafana/releases/%s" % rel["id"], payload)
else:
    call("POST", "/repos/grafana/grafana/releases", payload)
url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
if url:
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""))
    try:
        urllib.request.urlopen(req).read()
    except urllib.error.HTTPError:
        pass
PY`
}

func parseUses(uses string) (owner, repo, path, ref string, err error) {
	parts := strings.Split(uses, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", "", fmt.Errorf("uses %q is not owner/repo[/path]@ref", uses)
	}
	segs := strings.Split(parts[0], "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return "", "", "", "", fmt.Errorf("uses %q is not owner/repo[/path]@ref", uses)
	}
	return segs[0], segs[1], strings.Join(segs[2:], "/"), parts[1], nil
}

func usesRef(uses string) string {
	_, _, _, ref, err := parseUses(uses)
	if err != nil {
		return ""
	}
	return ref
}

func effectivePerms(job map[string]string) map[string]string {
	out := map[string]string{"contents": "none", "id-token": "none"}
	for k, v := range job {
		out[k] = v
	}
	return out
}

func exceeds(requested, max map[string]string) bool {
	rank := map[string]int{"": 0, "none": 0, "read": 1, "write": 2}
	for k, req := range requested {
		if rank[req] > rank[max[k]] {
			return true
		}
	}
	return false
}

func jobRuns(ifExpr string, in releaseInputs) bool {
	e := strings.ReplaceAll(ifExpr, " ", "")
	if e == "" {
		return true
	}
	if strings.Contains(e, "inputs.latest=='1'") {
		return !in.dryRun && in.latest == "1"
	}
	if strings.Contains(e, "github.event_name=='push'") {
		return in.event == "push"
	}
	if strings.Contains(e, "inputs.version!=''") {
		return in.version != ""
	}
	return true
}

func evalMap(with map[string]any, in releaseInputs, api *releaseAPI) map[string]string {
	out := map[string]string{}
	for k, v := range with {
		out[k] = subst(fmt.Sprint(v), nil, in, api)
	}
	return out
}

func subst(s string, inputs map[string]string, in releaseInputs, api *releaseAPI) string {
	dry := "false"
	if in.dryRun {
		dry = "true"
	}
	tokenInput := ""
	if inputs != nil {
		tokenInput = inputs["token"]
	}
	repl := map[string]string{
		"${{ secrets.GITHUB_TOKEN }}": jobToken,
		"${{ github.token }}":         jobToken,
		"${{ inputs.token }}":         tokenInput,
		"${{ inputs.version }}":       in.version,
		"${{ inputs.latest }}":        in.latest,
		"${{ inputs.dry_run }}":       dry,
	}
	if api != nil {
		repl["${{ inputs.api }}"] = api.server.URL
	}
	for k, v := range inputs {
		repl["${{ inputs."+k+" }}"] = v
	}
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

func orderJobs(t *testing.T, jobs map[string]jobYAML) []string {
	t.Helper()
	pending := map[string]jobYAML{}
	for name, job := range jobs {
		pending[name] = job
	}
	var ordered []string
	for len(pending) > 0 {
		progress := false
		for name, job := range pending {
			ready := true
			for _, need := range needList(job.Needs) {
				if _, ok := pending[need]; ok {
					ready = false
					break
				}
			}
			if ready {
				ordered = append(ordered, name)
				delete(pending, name)
				progress = true
			}
		}
		if !progress {
			t.Fatalf("cycle in job needs: %v", pending)
		}
	}
	return ordered
}

func needList(node yaml.Node) []string {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "" {
			return nil
		}
		return []string{node.Value}
	case yaml.SequenceNode:
		var out []string
		for _, n := range node.Content {
			out = append(out, n.Value)
		}
		return out
	default:
		return nil
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "github-release.yml")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rootFromTest(t *testing.T) string {
	t.Helper()
	return repoRoot(t)
}
