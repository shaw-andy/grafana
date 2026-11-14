package githubactions

import (
	"io"
	"net/http"
	"net/http/httptest"
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

// These tests follow a non-draft pull_request through .github/workflows and run
// the action resolved from the uses ref. The action reads its token input the
// way the published pr-checks bundle does, then calls the commit status, check
// run, and workflow-run cancel endpoints with that token.
//
// A fixed workflow pins pr-checks to a full commit SHA and does not grant the
// job actions: write. Until then the moving main ref is what runs, and the job
// token is allowed to cancel a workflow run.

const (
	workflowRepo = "grafana/grafana"
	actionRepo   = "grafana/grafana-github-actions"
	actionPath   = "pr-checks"
)

func TestNonDraftPullRequestDoesNotRunMutablePRChecksWithWorkflowWrite(t *testing.T) {
	root := repoRoot(t)
	actions := newActionRepository(t)
	api := newTokenAPI()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	for _, activity := range []string{"opened", "synchronize", "reopened", "labeled", "unlabeled"} {
		t.Run(activity, func(t *testing.T) {
			api.reset()
			report := runPullRequest(t, root, actions, srv.URL, api, pullRequest{
				activity:   activity,
				draft:      false,
				fork:       false,
				repository: workflowRepo,
			})

			if _, ok := report.prChecks(); !ok {
				t.Fatalf("pull_request %s on a non-draft same-repository pull request did not select the pr-checks job", activity)
			}
			for _, job := range report.jobs {
				if job.ranMutable {
					t.Errorf("%s job %s executed %s, resolved to %s, which is not a full commit SHA written in the workflow", job.workflow, job.id, job.ref, job.resolvedSHA)
				}
				if job.statusCreated || job.checkCreated || job.runCanceled {
					t.Errorf("%s job %s created a commit status=%v, created a check run=%v, canceled a workflow run=%v", job.workflow, job.id, job.statusCreated, job.checkCreated, job.runCanceled)
				}
				if api.canceled(job.token) {
					t.Errorf("job token for %s/%s is allowed to cancel a workflow run in %s", job.workflow, job.id, job.repository)
				}
				if !api.crossRepoDenied(job.token) {
					t.Errorf("job token for %s/%s authorized a workflow-run cancel in a repository other than %s", job.workflow, job.id, job.repository)
				}
			}
		})
	}
}

func TestDraftPullRequestDoesNotRunPRChecks(t *testing.T) {
	root := repoRoot(t)
	actions := newActionRepository(t)
	api := newTokenAPI()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	report := runPullRequest(t, root, actions, srv.URL, api, pullRequest{
		activity:   "opened",
		draft:      true,
		fork:       false,
		repository: workflowRepo,
	})
	if _, ok := report.prChecks(); ok {
		t.Fatal("draft pull request selected the pr-checks job")
	}
	if api.callCount() != 0 {
		t.Fatalf("draft pull request performed %d API calls", api.callCount())
	}
}

func TestJobIfMatchesBooleanEquality(t *testing.T) {
	// actions/runner v2.338.2 wraps a job if that does not call a status function
	// as success() && (<condition>). Boolean == compares the two boolean values.
	cond := wrapJobIf("github.event.pull_request.draft == false")
	if !evalCondition(t, cond, eventContext("opened", false)) {
		t.Fatalf("%q was false for a non-draft pull request", cond)
	}
	if evalCondition(t, cond, eventContext("opened", true)) {
		t.Fatalf("%q was true for a draft pull request", cond)
	}
}

func TestBranchRefResolvesToTipAfterCommit(t *testing.T) {
	actions := newActionRepository(t)
	if got := actions.revParse(t, "main"); got != actions.attacker {
		t.Fatalf("main resolved to %s, attacker tip is %s", got, actions.attacker)
	}
	if got := actions.revParse(t, actions.benign); got != actions.benign {
		t.Fatalf("pinned benign SHA resolved to %s", got)
	}
}

type pullRequest struct {
	activity   string
	draft      bool
	fork       bool
	repository string
}

type jobResult struct {
	workflow      string
	id            string
	ref           string
	resolvedSHA   string
	ranMutable    bool
	token         string
	repository    string
	statusCreated bool
	checkCreated  bool
	runCanceled   bool
	prChecks      bool
}

type runReport struct {
	jobs []jobResult
}

func (r runReport) prChecks() (jobResult, bool) {
	for _, job := range r.jobs {
		if job.prChecks {
			return job, true
		}
	}
	return jobResult{}, false
}

type actionRepository struct {
	dir      string
	benign   string
	attacker string
}

func newActionRepository(t *testing.T) actionRepository {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=actions-fixture",
			"GIT_AUTHOR_EMAIL=actions-fixture@example.com",
			"GIT_COMMITTER_NAME=actions-fixture",
			"GIT_COMMITTER_EMAIL=actions-fixture@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-b", "main")
	writeAction(t, dir, false)
	git("add", ".")
	git("commit", "-m", "reviewed pr-checks")
	benign := git("rev-parse", "HEAD")
	writeAction(t, dir, true)
	git("add", ".")
	git("commit", "-m", "changed pr-checks on main")
	attacker := git("rev-parse", "HEAD")
	if benign == attacker {
		t.Fatal("attacker commit did not move main")
	}
	return actionRepository{dir: dir, benign: benign, attacker: attacker}
}

func (a actionRepository) revParse(t *testing.T, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", a.dir, "rev-parse", "--verify", ref+"^{commit}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (a actionRepository) show(t *testing.T, sha, path string) []byte {
	t.Helper()
	cmd := exec.Command("git", "-C", a.dir, "show", sha+":"+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git show %s:%s: %v\n%s", sha, path, err, out)
	}
	return out
}

func writeAction(t *testing.T, dir string, attack bool) {
	t.Helper()
	base := filepath.Join(dir, actionPath)
	if err := os.MkdirAll(filepath.Join(base, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	const actionYAML = "name: PR Checks\ninputs:\n  token:\n    default: ${{ github.token }}\nruns:\n  using: node24\n  main: dist/index.js\n"
	if err := os.WriteFile(filepath.Join(base, "action.yml"), []byte(actionYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	script := benignScript
	if attack {
		script = attackerScript
	}
	if err := os.WriteFile(filepath.Join(base, "dist", "index.js"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
}

// attackerScript is the replacement pr-checks program on the actions
// repository main branch. getInput matches the function bundled in
// pr-checks/dist/index.js at af3213823a725b60b60947211de51d0fa3959391. The
// Authorization header matches the bundled @octokit/auth-token prefix.
const attackerScript = `
function getInput(name, options) {
  const val = process.env["INPUT_" + name.replace(/ /g, "_").toUpperCase()] || "";
  if (options && options.required && !val) {
    throw new Error("Input required and not supplied: " + name);
  }
  if (options && options.trimWhitespace === false) {
    return val;
  }
  return val.trim();
}
const token = getInput("token", { required: true });
const api = process.env.GHA_API_URL;
const repo = process.env.GHA_REPOSITORY;
async function call(path) {
  await fetch(api + path, {
    method: "POST",
    headers: {
      authorization: "token " + token,
      "content-type": "application/json",
    },
    body: "{}",
  });
}
await call("/repos/" + repo + "/statuses/0123456789abcdef0123456789abcdef01234567");
await call("/repos/" + repo + "/check-runs");
await call("/repos/" + repo + "/actions/runs/1/cancel");
await call("/repos/other/repo/actions/runs/1/cancel");
`

const benignScript = "process.exit(0)\n"

type jobCredential struct {
	repository string
	scopes     map[string]string
}

type apiCall struct {
	token  string
	path   string
	status int
}

type tokenAPI struct {
	mu     sync.Mutex
	tokens map[string]jobCredential
	seen   []apiCall
}

func newTokenAPI() *tokenAPI {
	return &tokenAPI{tokens: map[string]jobCredential{}}
}

func (a *tokenAPI) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens = map[string]jobCredential{}
	a.seen = nil
}

func (a *tokenAPI) issue(token string, job jobCredential) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[token] = job
}

func (a *tokenAPI) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}

func (a *tokenAPI) canceled(token string) bool {
	return a.saw(token, "/repos/"+workflowRepo+"/actions/runs/1/cancel", http.StatusAccepted)
}

func (a *tokenAPI) crossRepoDenied(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	found := false
	for _, call := range a.seen {
		if call.token == token && strings.Contains(call.path, "/repos/other/repo/") {
			found = true
			if call.status != http.StatusForbidden {
				return false
			}
		}
	}
	return found
}

func (a *tokenAPI) saw(token, path string, status int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, call := range a.seen {
		if call.token == token && call.path == path && call.status == status {
			return true
		}
	}
	return false
}

func (a *tokenAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "token ")
	if !ok || token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	job, known := a.tokens[token]
	a.mu.Unlock()
	status := http.StatusForbidden
	if known && repositoryOf(r.URL.Path) == job.repository && allows(r.URL.Path, job.scopes) {
		status = successStatus(r.URL.Path)
	}
	a.mu.Lock()
	a.seen = append(a.seen, apiCall{token: token, path: r.URL.Path, status: status})
	a.mu.Unlock()
	w.WriteHeader(status)
}

func repositoryOf(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "repos" {
		return ""
	}
	return parts[1] + "/" + parts[2]
}

func allows(path string, scopes map[string]string) bool {
	switch {
	case strings.Contains(path, "/statuses/"):
		return scopes["statuses"] == "write"
	case strings.HasSuffix(path, "/check-runs"):
		return scopes["checks"] == "write"
	case strings.HasSuffix(path, "/cancel"):
		return scopes["actions"] == "write"
	default:
		return false
	}
}

func successStatus(path string) int {
	if strings.HasSuffix(path, "/cancel") {
		return http.StatusAccepted
	}
	return http.StatusCreated
}

func runPullRequest(t *testing.T, root string, actions actionRepository, apiURL string, api *tokenAPI, pr pullRequest) runReport {
	t.Helper()
	var report runReport
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !workflowWants(doc, pr.activity) {
			continue
		}
		workflowPerms, workflowPermsSet := permissionsOf(doc)
		jobs, _ := doc["jobs"].(map[string]any)
		for id, raw := range jobs {
			job, _ := raw.(map[string]any)
			if job == nil {
				continue
			}
			perms, ok := permissionsOf(job)
			if !ok {
				if !workflowPermsSet {
					continue
				}
				perms = workflowPerms
			}
			perms = applyForkRule(perms, pr)
			// The pr-checks job is always exercised, including after actions: write
			// is removed. Other jobs are exercised when they grant that same
			// combination, so a second copy of the bug cannot pass unnoticed.
			if !jobUsesPRChecks(job) && !sharesPRChecksPermissions(perms) {
				continue
			}
			if !jobSelected(t, job, pr) {
				continue
			}
			token := "job-token-" + name + "-" + id
			api.issue(token, jobCredential{repository: pr.repository, scopes: perms})
			result := jobResult{
				workflow:   name,
				id:         id,
				token:      token,
				repository: pr.repository,
				prChecks:   jobUsesPRChecks(job),
			}
			runJobSteps(t, actions, apiURL, api, pr, job, token, &result)
			probe(t, apiURL, token, "/repos/"+pr.repository+"/actions/runs/1/cancel")
			probe(t, apiURL, token, "/repos/other/repo/actions/runs/1/cancel")
			if api.canceled(token) {
				result.runCanceled = true
			}
			report.jobs = append(report.jobs, result)
		}
	}
	return report
}

func runJobSteps(t *testing.T, actions actionRepository, apiURL string, api *tokenAPI, pr pullRequest, job map[string]any, token string, result *jobResult) {
	t.Helper()
	steps, _ := job["steps"].([]any)
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		uses, _ := step["uses"].(string)
		if uses == "" {
			continue
		}
		if isPRChecksUses(uses) {
			result.prChecks = true
			if ref, ok := usesRef(uses); ok {
				result.ref = ref
			}
		}
		runStep(t, actions, apiURL, api, pr, step, uses, token, result)
	}
}

func runStep(t *testing.T, actions actionRepository, apiURL string, api *tokenAPI, pr pullRequest, step map[string]any, uses, token string, result *jobResult) {
	t.Helper()
	_, path, ref, external := parseUses(uses)
	if !external || isFullSHA(ref) {
		return
	}
	resolved := actions.revParse(t, ref)
	if resolved != actions.attacker {
		t.Fatalf("ref %s resolved to %s, want main after the actions repository changed (%s)", ref, resolved, actions.attacker)
	}
	result.ranMutable = true
	result.resolvedSHA = resolved
	result.ref = ref

	inputs := evaluateInputs(step["with"], token)
	var manifest map[string]any
	if err := yaml.Unmarshal(actions.show(t, resolved, path+"/action.yml"), &manifest); err != nil {
		t.Fatal(err)
	}
	if inputs["token"] == "" {
		if def := tokenDefault(manifest); def != "" {
			inputs["token"] = evaluateExpression(def, token)
		}
	}

	dir := t.TempDir()
	script := actions.show(t, resolved, path+"/dist/index.js")
	if !strings.Contains(string(script), "getInput") {
		t.Fatalf("resolved %s did not contain the changed action program:\n%s", resolved, script)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), script, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "index.js")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"INPUT_TOKEN="+inputs["token"],
		"GHA_API_URL="+apiURL,
		"GHA_REPOSITORY="+pr.repository,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("action at %s: %v\n%s", resolved, err, out)
	}
	statusPath := "/repos/" + pr.repository + "/statuses/0123456789abcdef0123456789abcdef01234567"
	checkPath := "/repos/" + pr.repository + "/check-runs"
	cancelPath := "/repos/" + pr.repository + "/actions/runs/1/cancel"
	result.statusCreated = api.saw(token, statusPath, http.StatusCreated)
	result.checkCreated = api.saw(token, checkPath, http.StatusCreated)
	result.runCanceled = api.saw(token, cancelPath, http.StatusAccepted)
}

func probe(t *testing.T, apiURL, token, path string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, apiURL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

func sharesPRChecksPermissions(perms map[string]string) bool {
	return perms["actions"] == "write" && (perms["checks"] == "write" || perms["statuses"] == "write")
}

func applyForkRule(perms map[string]string, pr pullRequest) map[string]string {
	if !pr.fork {
		return perms
	}
	out := make(map[string]string, len(perms))
	for key, level := range perms {
		if level == "write" {
			out[key] = "read"
			continue
		}
		out[key] = level
	}
	return out
}

func workflowWants(doc map[string]any, activity string) bool {
	on, ok := doc["on"].(map[string]any)
	if !ok {
		return false
	}
	raw, ok := on["pull_request"]
	if !ok {
		return false
	}
	types := []string{"opened", "synchronize", "reopened"}
	if spec, ok := raw.(map[string]any); ok {
		if listed, ok := spec["types"].([]any); ok && len(listed) > 0 {
			types = types[:0]
			for _, item := range listed {
				if s, ok := item.(string); ok {
					types = append(types, s)
				}
			}
		}
	}
	for _, typ := range types {
		if typ == activity {
			return true
		}
	}
	return false
}

func jobSelected(t *testing.T, job map[string]any, pr pullRequest) bool {
	t.Helper()
	raw, ok := job["if"]
	if !ok {
		return true
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return evalCondition(t, wrapJobIf(v), eventContext(pr.activity, pr.draft))
	default:
		t.Fatalf("unsupported job if %T", raw)
		return false
	}
}

func jobUsesPRChecks(job map[string]any) bool {
	steps, _ := job["steps"].([]any)
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		if uses, ok := step["uses"].(string); ok && isPRChecksUses(uses) {
			return true
		}
	}
	if uses, ok := job["uses"].(string); ok && isPRChecksUses(uses) {
		return true
	}
	return false
}

func isPRChecksUses(uses string) bool {
	name, path, _, external := parseUses(uses)
	return external && name == actionRepo && path == actionPath
}

func usesRef(uses string) (string, bool) {
	_, _, ref, external := parseUses(uses)
	if !external {
		return "", false
	}
	return ref, true
}

func parseUses(uses string) (name, path, ref string, external bool) {
	if strings.HasPrefix(uses, "docker://") || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, `.\\`) || strings.HasPrefix(uses, "$/") {
		return "", "", "", false
	}
	segments := strings.Split(uses, "@")
	if len(segments) != 2 || segments[1] == "" {
		return "", "", "", false
	}
	pathSegments := strings.FieldsFunc(segments[0], func(r rune) bool { return r == '/' || r == '\\' })
	if len(pathSegments) < 2 {
		return "", "", "", false
	}
	return pathSegments[0] + "/" + pathSegments[1], strings.Join(pathSegments[2:], "/"), segments[1], true
}

func isFullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func permissionsOf(node map[string]any) (map[string]string, bool) {
	raw, ok := node["permissions"]
	if !ok || raw == nil {
		return nil, false
	}
	switch v := raw.(type) {
	case string:
		level := "none"
		switch v {
		case "read-all":
			level = "read"
		case "write-all":
			level = "write"
		}
		out := map[string]string{}
		for _, key := range []string{"actions", "checks", "contents", "statuses", "pull-requests"} {
			out[key] = level
		}
		return out, true
	case map[string]any:
		out := map[string]string{}
		for key, value := range v {
			s, ok := value.(string)
			if ok {
				out[key] = s
			}
		}
		return out, true
	default:
		return map[string]string{}, true
	}
}

func evaluateInputs(raw any, token string) map[string]string {
	out := map[string]string{}
	with, _ := raw.(map[string]any)
	for key, value := range with {
		s, ok := value.(string)
		if ok {
			out[key] = evaluateExpression(s, token)
		}
	}
	return out
}

func tokenDefault(manifest map[string]any) string {
	inputs, _ := manifest["inputs"].(map[string]any)
	token, _ := inputs["token"].(map[string]any)
	def, _ := token["default"].(string)
	return def
}

var (
	secretTokenExpr = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}`)
	githubTokenExpr = regexp.MustCompile(`(?i)\$\{\{\s*github\.token\s*\}\}`)
)

func evaluateExpression(s, token string) string {
	s = secretTokenExpr.ReplaceAllLiteralString(s, token)
	s = githubTokenExpr.ReplaceAllLiteralString(s, token)
	return s
}

func eventContext(activity string, draft bool) map[string]any {
	return map[string]any{
		"github": map[string]any{
			"repository": workflowRepo,
			"event_name": "pull_request",
			"event": map[string]any{
				"action": activity,
				"pull_request": map[string]any{
					"draft": draft,
					"head": map[string]any{
						"repo": map[string]any{
							"fork":      false,
							"full_name": workflowRepo,
						},
					},
				},
			},
		},
	}
}

func wrapJobIf(condition string) string {
	condition = strings.TrimSpace(condition)
	if strings.HasPrefix(condition, "${{") && strings.HasSuffix(condition, "}}") {
		condition = strings.TrimSpace(condition[3 : len(condition)-2])
	}
	lower := strings.ToLower(condition)
	for _, fn := range []string{"success(", "failure(", "cancelled(", "always("} {
		if strings.Contains(lower, fn) {
			return condition
		}
	}
	return "success() && (" + condition + ")"
}

func evalCondition(t *testing.T, condition string, ctx map[string]any) bool {
	t.Helper()
	p := &parser{s: condition, ctx: ctx}
	value := p.parseOr()
	p.skip()
	if p.i != len(p.s) {
		t.Fatalf("unparsed job if %q at %q", condition, p.s[p.i:])
	}
	b, ok := value.(bool)
	if !ok {
		t.Fatalf("job if %q evaluated to %#v", condition, value)
	}
	return b
}

type parser struct {
	s   string
	i   int
	ctx map[string]any
}

func (p *parser) parseOr() any {
	left := p.parseAnd()
	for {
		p.skip()
		if !strings.HasPrefix(p.rest(), "||") {
			return left
		}
		p.i += 2
		right := p.parseAnd()
		lb, lok := left.(bool)
		rb, rok := right.(bool)
		if !lok || !rok {
			return false
		}
		left = lb || rb
	}
}

func (p *parser) parseAnd() any {
	left := p.parseUnary()
	for {
		p.skip()
		if !strings.HasPrefix(p.rest(), "&&") {
			return left
		}
		p.i += 2
		right := p.parseUnary()
		lb, lok := left.(bool)
		rb, rok := right.(bool)
		if !lok || !rok {
			return false
		}
		left = lb && rb
	}
}

func (p *parser) parseUnary() any {
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '!' && (p.i+1 >= len(p.s) || p.s[p.i+1] != '=') {
		p.i++
		value := p.parseUnary()
		b, ok := value.(bool)
		if !ok {
			return false
		}
		return !b
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() any {
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		value := p.parseOr()
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ')' {
			p.i++
		}
		return value
	}
	left := p.parseValue()
	p.skip()
	op := ""
	switch {
	case strings.HasPrefix(p.rest(), "=="):
		op = "=="
	case strings.HasPrefix(p.rest(), "!="):
		op = "!="
	}
	if op == "" {
		return left
	}
	p.i += len(op)
	right := p.parseValue()
	eq := abstractEqual(left, right)
	if op == "!=" {
		return !eq
	}
	return eq
}

func (p *parser) parseValue() any {
	p.skip()
	if p.i >= len(p.s) {
		return nil
	}
	if p.s[p.i] == '\'' || p.s[p.i] == '"' {
		return p.parseString()
	}
	start := p.i
	for p.i < len(p.s) && isWord(p.s[p.i]) {
		p.i++
	}
	word := p.s[start:p.i]
	if word == "" {
		return nil
	}
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ')' {
			p.i++
		}
		if strings.EqualFold(word, "success") || strings.EqualFold(word, "always") {
			return true
		}
		return false
	}
	switch word {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	cur := any(p.ctx)
	for _, part := range strings.Split(word, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = obj[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func (p *parser) parseString() string {
	quote := p.s[p.i]
	p.i++
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != quote {
		p.i++
	}
	s := p.s[start:p.i]
	if p.i < len(p.s) {
		p.i++
	}
	return s
}

func (p *parser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) rest() string {
	if p.i >= len(p.s) {
		return ""
	}
	return p.s[p.i:]
}

func isWord(c byte) bool {
	return c == '.' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func abstractEqual(left, right any) bool {
	lb, lok := left.(bool)
	rb, rok := right.(bool)
	if lok || rok {
		return lok && rok && lb == rb
	}
	ls, lok := left.(string)
	rs, rok := right.(string)
	return lok && rok && strings.EqualFold(ls, rs)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
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
