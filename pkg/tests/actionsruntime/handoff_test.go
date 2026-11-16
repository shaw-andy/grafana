package actionsruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests exercise the release-token handoff. They fail while a job that
// mints a GitHub App installation token runs actions/github-script from a
// moving ref: the runner passes action inputs through to that ref's code, and
// the same job can also request an OIDC token. Pinning actions/github-script
// to a full commit SHA makes the ref's code fixed and these tests pass.
//
// Other moving refs that receive an app-token output are not covered here:
// actions/checkout@v5 (create-security-branch.yml, create-release-branch.yml,
// release-pr.yml), actions/setup-go@v7.0.0 (release-pr.yml),
// grafana/grafana-github-actions/crowdin-download@main,
// grafana/grafana-github-actions/commands@main, grafana/auto-triager@main,
// grafana/grafana-github-actions-go/migrate-open-prs@main, and
// grafana/grafana-github-actions-go/bump-release@main.

func TestFullSHAPinIsNotAMovingTag(t *testing.T) {
	t.Parallel()
	if _, ok := movingGitHubScript("actions/github-script@0123456789abcdef0123456789abcdef01234567"); ok {
		t.Fatal("full commit SHA was treated as a moving tag")
	}
	ref, ok := movingGitHubScript("actions/github-script@v8")
	if !ok || ref != "v8" {
		t.Fatalf("v8 ref = %q, %v", ref, ok)
	}
}

func TestReleaseDownstreamJobRunsOnlyForGrafanaMainAndPatchedMirror(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	wf := loadWorkflow(t, filepath.Join(root, ".github/workflows/release-build.yml"))
	cases := []struct {
		name  string
		sc    scenario
		runs  bool
	}{
		{name: "grafana main push", sc: scenario{repository: "grafana/grafana", refName: "main", event: "push"}, runs: true},
		{name: "grafana main schedule", sc: scenario{repository: "grafana/grafana", refName: "main", event: "schedule"}, runs: true},
		{name: "grafana main dispatch", sc: scenario{repository: "grafana/grafana", refName: "main", event: "workflow_dispatch"}, runs: true},
		{name: "grafana release branch", sc: scenario{repository: "grafana/grafana", refName: "release-13.0.0", event: "push"}, runs: false},
		{name: "fork main push", sc: scenario{repository: "shaw-andy/grafana", refName: "main", event: "push"}, runs: false},
		{name: "security mirror patched", sc: scenario{repository: "grafana/grafana-security-mirror", refName: "release-13.0.0#patched", event: "push"}, runs: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jobRuns(wf, "downstream", tc.sc)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.runs {
				t.Fatalf("downstream ran=%v, want %v", got, tc.runs)
			}
		})
	}
}

func TestMovingGitHubScriptTagCanUseTheInstallationToken(t *testing.T) {
	root := repoRoot(t)
	for _, sc := range handoffScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			wf := loadWorkflow(t, filepath.Join(root, sc.file))
			ran, err := jobRuns(wf, sc.job, sc)
			if err != nil {
				t.Fatal(err)
			}
			if ran != sc.expectRuns {
				t.Fatalf("job %s ran=%v, want %v", sc.job, ran, sc.expectRuns)
			}
			if sc.file == ".github/workflows/release-build.yml" && sc.event == "push" && sc.repository == "grafana/grafana" && sc.refName == "main" {
				assertReleaseScriptUsesWorkflowCommit(t, wf)
			}
			if !ran {
				return
			}
			leaks := exerciseRunningSteps(t, root, sc, wf)
			if leaks != 0 {
				t.Errorf("%d attacker-chosen request(s) were sent with the installation token", leaks)
			}
		})
	}
}

func assertReleaseScriptUsesWorkflowCommit(t *testing.T, wf map[string]any) {
	t.Helper()
	job := jobMap(t, wf, "downstream")
	var script string
	for _, step := range stepsOf(job) {
		if strings.HasPrefix(asString(step["uses"]), "actions/github-script@") && containsTokenRef(step["with"]) {
			script = asString(nested(step, "with", "script"))
		}
	}
	if script == "" {
		t.Fatal("downstream github-script step has no script")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "run-script.mjs")
	if err := os.WriteFile(program, []byte(releaseScriptRunner), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", program)
	cmd.Env = append(os.Environ(),
		"WORKFLOW_SCRIPT="+script,
		"REF=main",
		"VERSION=1.0.0",
		"BUILD_ID=100",
		"BUCKET=grafana-prerelease",
		"GRAFANA_COMMIT=workflow-commit",
		"PUBLIC_COMMIT=workflow-commit",
		"SOURCE_EVENT=push",
		"REPO=grafana/grafana",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("workflow script failed: %v\n%s", err, out)
	}
	if bytes.Contains(out, []byte("attacker-chosen-commit")) {
		t.Fatalf("workflow script itself sent the attacker commit: %s", out)
	}
	var calls []map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &calls); err != nil {
		t.Fatalf("script output %s: %v", out, err)
	}
	if len(calls) != 1 || calls[0]["workflow_id"] != "release-build-pro.yml" {
		t.Fatalf("push on main dispatched %#v", calls)
	}
	inputs, _ := calls[0]["inputs"].(map[string]any)
	if inputs["grafana-commit"] != "workflow-commit" {
		t.Fatalf("script commit = %#v", inputs["grafana-commit"])
	}
}

const releaseScriptRunner = `
const calls = [];
const github = { rest: { actions: { createWorkflowDispatch: async (args) => { calls.push(args); } } } };
const core = { info() {}, setFailed(message) { throw new Error(message); } };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const fn = new AsyncFunction("github", "core", process.env.WORKFLOW_SCRIPT);
await fn(github, core);
process.stdout.write(JSON.stringify(calls));
`

type scenario struct {
	name       string
	file       string
	job        string
	repository string
	refName    string
	baseRef    string
	event      string
	fork       bool
	headFull   string
	changed    []string
	outputs    map[string]map[string]string
	expectRuns bool
}

func handoffScenarios() []scenario {
	return []scenario{
		{name: "release main push", file: ".github/workflows/release-build.yml", job: "downstream", repository: "grafana/grafana", refName: "main", event: "push", expectRuns: true},
		{name: "release main schedule", file: ".github/workflows/release-build.yml", job: "downstream", repository: "grafana/grafana", refName: "main", event: "schedule", expectRuns: true},
		{name: "release main dispatch", file: ".github/workflows/release-build.yml", job: "downstream", repository: "grafana/grafana", refName: "main", event: "workflow_dispatch", expectRuns: true},
		{name: "release branch push", file: ".github/workflows/release-build.yml", job: "downstream", repository: "grafana/grafana", refName: "release-13.0.0", event: "push", expectRuns: false},
		{name: "release fork push", file: ".github/workflows/release-build.yml", job: "downstream", repository: "shaw-andy/grafana", refName: "main", event: "push", expectRuns: false},
		{name: "release mirror patched", file: ".github/workflows/release-build.yml", job: "downstream", repository: "grafana/grafana-security-mirror", refName: "release-13.0.0#patched", event: "push", expectRuns: true},
		{name: "mirror sync main", file: ".github/workflows/sync-mirror-event.yml", job: "dispatch-job", repository: "grafana/grafana", refName: "main", event: "push", expectRuns: true},
		{name: "mirror sync release", file: ".github/workflows/sync-mirror-event.yml", job: "dispatch-job", repository: "grafana/grafana", refName: "release-12.0.0", event: "push", expectRuns: true},
		{name: "mirror sync fork", file: ".github/workflows/sync-mirror-event.yml", job: "dispatch-job", repository: "shaw-andy/grafana", refName: "main", event: "push", expectRuns: false},
		{name: "patch check same repo", file: ".github/workflows/pr-patch-check.yml", job: "dispatch-job", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", headFull: "grafana/grafana", expectRuns: true},
		{name: "patch check fork", file: ".github/workflows/pr-patch-check.yml", job: "dispatch-job", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", fork: true, headFull: "attacker/grafana", expectRuns: false},
		{name: "levitate breaking", file: ".github/workflows/detect-breaking-changes-levitate.yml", job: "Report", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", headFull: "grafana/grafana", changed: []string{"packages/data/foo.ts"}, outputs: map[string]map[string]string{"levitate-run": {"exit_code": "1"}, "does-label-exist": {"result": "0"}}, expectRuns: true},
		{name: "levitate clean", file: ".github/workflows/detect-breaking-changes-levitate.yml", job: "Report", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", headFull: "grafana/grafana", changed: []string{"packages/data/foo.ts"}, outputs: map[string]map[string]string{"levitate-run": {"exit_code": "0"}, "does-label-exist": {"result": "1"}}, expectRuns: true},
		{name: "levitate fork", file: ".github/workflows/detect-breaking-changes-levitate.yml", job: "Report", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", fork: true, headFull: "attacker/grafana", changed: []string{"packages/data/foo.ts"}, expectRuns: false},
		{name: "security patch with vul", file: ".github/workflows/create-security-patch-from-security-mirror.yml", job: "dispatch-create-patch", repository: "grafana/grafana-security-mirror", refName: "100/merge", baseRef: "main", event: "pull_request", headFull: "grafana/grafana-security-mirror", outputs: map[string]map[string]string{"labels": {"vul_id": "VUL-2026-0001"}}, expectRuns: true},
		{name: "security patch outside mirror", file: ".github/workflows/create-security-patch-from-security-mirror.yml", job: "dispatch-create-patch", repository: "grafana/grafana", refName: "100/merge", baseRef: "main", event: "pull_request", headFull: "grafana/grafana", expectRuns: false},
	}
}

func exerciseRunningSteps(t *testing.T, root string, sc scenario, wf map[string]any) int {
	t.Helper()
	job := jobMap(t, wf, sc.job)
	steps := stepsOf(job)
	mint := findMint(steps, nil)
	idToken := idTokenWrite(job)
	var leaks int
	for _, step := range steps {
		uses := asString(step["uses"])
		if _, ok := movingGitHubScript(uses); !ok {
			continue
		}
		referenced := containsTokenRef(step["with"]) || containsTokenRef(step["env"])
		if !referenced && !(idToken && mint != nil) {
			continue
		}
		runs, err := stepRuns(step, sc)
		if err != nil {
			t.Fatal(err)
		}
		if !runs {
			continue
		}
		chosen := mint
		if referenced {
			if specific := findMint(steps, step); specific != nil {
				chosen = specific
			}
		}
		if chosen == nil {
			t.Fatalf("step %s has no create-github-app-token step", stepLabel(step))
		}
		app := asString(nested(chosen, "with", "github_app"))
		permExpr := asString(nested(chosen, "with", "permission_set"))
		if strings.TrimSpace(permExpr) == "" {
			permExpr = "default"
		}
		permValue, err := evalExpr(permExpr, sc.exprCtx())
		if err != nil {
			t.Fatal(err)
		}
		perm := fmt.Sprint(permValue)
		spec := attackFor(sc.file, app, perm, pathBase(sc.repository))
		modes := []string{}
		if referenced {
			modes = append(modes, "passed")
		}
		if idToken {
			modes = append(modes, "oidc")
		}
		for _, mode := range modes {
			if got := runAttack(t, root, sc, spec, mode, referenced); got {
				leaks++
				t.Errorf("%s step %q (%s) mode %s: moving %s used the installation token for an attacker-chosen call", sc.file, stepLabel(step), uses, mode, uses)
			}
		}
	}
	return leaks
}

func runAttack(t *testing.T, root string, sc scenario, spec attackSpec, mode string, referenced bool) bool {
	t.Helper()
	var records []recorded
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		records = append(records, recorded{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, auth: r.Header.Get("Authorization"), body: string(body)})
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"value":"placeholder-oidc-jwt"}`)
		case r.URL.Path == "/v1/auth/github-actions-oidc/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"auth":{"client_token":"placeholder-vault-token"}}`)
		case strings.HasPrefix(r.URL.Path, "/v1/github-app-"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"data":{"token":%q}}`, installationPlaceholder(r.URL.Path))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	data := testdataDir(t)
	specRaw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	resultFile := filepath.Join(t.TempDir(), "minted")
	baseEnv := []string{
		"MODE=mint",
		"ATTACK_SPEC=" + string(specRaw),
		"MINT_RESULT=" + resultFile,
		"VAULT_URL=" + server.URL,
		"GITHUB_API_URL=" + server.URL,
		"ACTIONS_ID_TOKEN_REQUEST_URL=" + server.URL + "/token?dummy=1",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=placeholder-oidc-request",
		"GITHUB_WORKFLOW_REF=" + workflowRef(sc),
		"NORMALIZE_SCRIPT=" + filepath.Join(data, "normalize_ref.sh"),
		"AUTH_VAULT_SCRIPT=" + filepath.Join(data, "auth_vault.sh"),
		"CREATE_TOKEN_SCRIPT=" + filepath.Join(data, "create_token.sh"),
		"PATH=" + os.Getenv("PATH"),
	}
	if out := runNode(t, filepath.Join(data, "attacker.mjs"), baseEnv); out != "" && !strings.Contains(out, "Create GitHub Token done") && !strings.Contains(out, "Vault auth done") {
		// mint writes the token to a file; stdout is the shell progress from the scripts.
	}
	minted, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("mint did not produce an installation token (%v). workflow ref %s", err, workflowRef(sc))
	}
	token := string(minted)
	if !strings.HasPrefix(token, "placeholder-installation-") {
		t.Fatal("minted value was not the installation-token placeholder")
	}

	input := "placeholder-job-token"
	if mode == "passed" && referenced {
		input = token
	}
	attackEnv := append([]string{}, baseEnv...)
	for i, entry := range attackEnv {
		if strings.HasPrefix(entry, "MODE=") {
			attackEnv[i] = "MODE=attack"
		}
	}
	if mode == "oidc" {
		attackEnv = append(attackEnv,
			"INPUT_GITHUB-TOKEN="+input,
		)
	} else {
		// Drop the OIDC endpoint so this mode only observes the value passed as the action input.
		filtered := attackEnv[:0]
		for _, entry := range attackEnv {
			if strings.HasPrefix(entry, "ACTIONS_ID_TOKEN_") {
				continue
			}
			filtered = append(filtered, entry)
		}
		attackEnv = append(filtered, "INPUT_GITHUB-TOKEN="+input)
	}
	before := len(records)
	runNode(t, filepath.Join(data, "attacker.mjs"), attackEnv)
	for _, rec := range records[before:] {
		if rec.method == http.MethodPost && strings.HasPrefix(rec.path, "/repos/") &&
			rec.auth == "token "+token && strings.Contains(rec.path+rec.body, "attacker-chosen-commit") {
			return true
		}
	}
	t.Fatalf("mode %s did not exercise the installation token (records after attack: %d)", mode, len(records)-before)
	return false
}

func runNode(t *testing.T, program string, env []string) string {
	t.Helper()
	cmd := exec.Command("node", program)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node %s: %v\n%s", filepath.Base(program), err, out)
	}
	return string(out)
}

type attackSpec struct {
	GitHubApp      string         `json:"githubApp"`
	PermissionSet  string         `json:"permissionSet"`
	RepositoryName string         `json:"repositoryName"`
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	Body           map[string]any `json:"body"`
}

func attackFor(file, app, perm, repositoryName string) attackSpec {
	spec := attackSpec{GitHubApp: app, PermissionSet: perm, RepositoryName: repositoryName, Method: http.MethodPost}
	switch filepath.Base(file) {
	case "sync-mirror-event.yml":
		spec.Path = "/repos/grafana/security-patch-actions/actions/workflows/mirror-branch-and-apply-patches.yml/dispatches"
		spec.Body = map[string]any{"ref": "main", "inputs": map[string]any{"src_sha": "attacker-chosen-commit"}}
	case "pr-patch-check.yml":
		spec.Path = "/repos/grafana/security-patch-actions/actions/workflows/test-patches-event.yml/dispatches"
		spec.Body = map[string]any{"ref": "main", "inputs": map[string]any{"src_pr_commit_sha": "attacker-chosen-commit"}}
	case "detect-breaking-changes-levitate.yml":
		spec.Path = "/repos/grafana/grafana/issues/attacker-chosen-issue/labels"
		spec.Body = map[string]any{"labels": []any{"attacker-chosen-commit"}}
	case "create-security-patch-from-security-mirror.yml":
		spec.Path = "/repos/grafana/security-patch-actions/actions/workflows/create-patch.yml/dispatches"
		spec.Body = map[string]any{"ref": "main", "inputs": map[string]any{"src_ref": "attacker-chosen-commit"}}
	default:
		spec.Path = "/repos/grafana/grafana-enterprise/actions/workflows/release-build-enterprise.yml/dispatches"
		spec.Body = map[string]any{"ref": "attacker-ref", "inputs": map[string]any{"grafana-commit": "attacker-chosen-commit"}}
	}
	return spec
}

type recorded struct {
	method   string
	path     string
	rawQuery string
	auth     string
	body     string
}

func installationPlaceholder(urlPath string) string {
	rest := strings.TrimPrefix(urlPath, "/v1/github-app-")
	app, tokenPart, ok := strings.Cut(rest, "/token/")
	if !ok {
		return "placeholder-installation-unknown"
	}
	match := regexp.MustCompile(`-([0-9a-f]{64})-(.+)$`).FindStringSubmatch(tokenPart)
	perm := "unknown"
	if match != nil {
		perm = match[2]
	}
	return "placeholder-installation-" + app + "-" + perm
}

func workflowRef(sc scenario) string {
	ref := "refs/heads/" + sc.refName
	if sc.event == "pull_request" {
		ref = "refs/pull/100/merge"
	}
	return sc.repository + "/" + sc.file + "@" + ref
}

func movingGitHubScript(uses string) (string, bool) {
	const prefix = "actions/github-script@"
	if !strings.HasPrefix(uses, prefix) {
		return "", false
	}
	ref := uses[len(prefix):]
	if regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(ref) {
		return ref, false
	}
	return ref, true
}

func idTokenWrite(job map[string]any) bool {
	perms, _ := job["permissions"].(map[string]any)
	return fmt.Sprint(perms["id-token"]) == "write"
}

func findMint(steps []map[string]any, consumer map[string]any) map[string]any {
	wantID := ""
	if consumer != nil {
		blob := flatten(consumer["with"]) + "\n" + flatten(consumer["env"])
		if match := regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.outputs\.token`).FindStringSubmatch(blob); match != nil {
			wantID = match[1]
		}
	}
	var first map[string]any
	for _, step := range steps {
		if !strings.Contains(asString(step["uses"]), "create-github-app-token") {
			continue
		}
		if first == nil {
			first = step
		}
		if wantID != "" && asString(step["id"]) == wantID {
			return step
		}
	}
	if wantID != "" {
		return nil
	}
	return first
}

func containsTokenRef(v any) bool {
	switch typed := v.(type) {
	case string:
		return strings.Contains(typed, ".outputs.token")
	case map[string]any:
		for _, child := range typed {
			if containsTokenRef(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsTokenRef(child) {
				return true
			}
		}
	}
	return false
}

func flatten(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			b.WriteString(typed)
			b.WriteByte('\n')
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(v)
	return b.String()
}

func jobRuns(wf map[string]any, name string, sc scenario) (bool, error) {
	if !workflowTriggered(wf, sc) {
		return false, nil
	}
	memo := map[string]bool{}
	var walk func(string) (bool, error)
	walk = func(jobName string) (bool, error) {
		if ran, ok := memo[jobName]; ok {
			return ran, nil
		}
		jobs, _ := wf["jobs"].(map[string]any)
		raw, ok := jobs[jobName].(map[string]any)
		if !ok {
			return false, fmt.Errorf("missing job %s", jobName)
		}
		for _, dep := range needNames(raw) {
			depRan, err := walk(dep)
			if err != nil {
				return false, err
			}
			if !depRan && !strings.Contains(asString(raw["if"]), "always()") {
				memo[jobName] = false
				return false, nil
			}
		}
		ifExpr := strings.TrimSpace(asString(raw["if"]))
		if ifExpr == "" {
			memo[jobName] = true
			return true, nil
		}
		value, err := evalExpr(ifExpr, sc.exprCtx())
		if err != nil {
			return false, fmt.Errorf("job %s if: %w", jobName, err)
		}
		memo[jobName] = truthy(value)
		return memo[jobName], nil
	}
	return walk(name)
}

func stepRuns(step map[string]any, sc scenario) (bool, error) {
	ifExpr := strings.TrimSpace(asString(step["if"]))
	if ifExpr == "" {
		return true, nil
	}
	value, err := evalExpr(ifExpr, sc.exprCtx())
	if err != nil {
		return false, fmt.Errorf("step %s if: %w", stepLabel(step), err)
	}
	return truthy(value), nil
}

func workflowTriggered(wf map[string]any, sc scenario) bool {
	on, ok := wf["on"].(map[string]any)
	if !ok {
		return false
	}
	switch sc.event {
	case "push":
		push, ok := on["push"].(map[string]any)
		if !ok {
			return false
		}
		return matchList(push["branches"], sc.refName, true)
	case "schedule":
		_, ok := on["schedule"]
		return ok && sc.refName == "main"
	case "workflow_dispatch":
		_, ok := on["workflow_dispatch"]
		return ok
	case "pull_request":
		pr, ok := on["pull_request"].(map[string]any)
		if !ok {
			return false
		}
		if !matchList(pr["branches"], sc.baseRef, true) {
			return false
		}
		return matchPaths(pr["paths"], sc.changed)
	default:
		return false
	}
}

func matchList(v any, name string, whenAbsent bool) bool {
	if v == nil {
		return whenAbsent
	}
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if globMatch(fmt.Sprint(item), name) {
			return true
		}
	}
	return false
}

func matchPaths(v any, changed []string) bool {
	if v == nil {
		return true
	}
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, file := range changed {
		for _, item := range list {
			if globMatch(fmt.Sprint(item), file) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '*' && i+1 < len(pattern) && pattern[i+1] == '*' {
			b.WriteString(".*")
			i++
			continue
		}
		if pattern[i] == '*' {
			b.WriteString("[^/]*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func (sc scenario) exprCtx() map[string]any {
	repoName := pathBase(sc.repository)
	steps := map[string]any{}
	for id, outputs := range sc.outputs {
		values := map[string]any{}
		for key, value := range outputs {
			values[key] = value
		}
		steps[id] = map[string]any{"outputs": values}
	}
	sourceEvent := ""
	if sc.event == "workflow_dispatch" {
		sourceEvent = "workflow_dispatch"
	}
	return map[string]any{
		"github": map[string]any{
			"repository": sc.repository,
			"ref_name":   sc.refName,
			"event_name": sc.event,
			"event": map[string]any{
				"repository": map[string]any{"name": repoName},
				"pull_request": map[string]any{
					"number": 100,
					"head": map[string]any{
						"repo": map[string]any{"fork": sc.fork, "full_name": sc.headFull},
					},
				},
			},
		},
		"inputs": map[string]any{"source-event": sourceEvent},
		"steps":  steps,
	}
}

func needNames(job map[string]any) []string {
	switch needs := job["needs"].(type) {
	case string:
		return []string{needs}
	case []any:
		names := make([]string, 0, len(needs))
		for _, item := range needs {
			names = append(names, fmt.Sprint(item))
		}
		return names
	default:
		return nil
	}
}

func stepsOf(job map[string]any) []map[string]any {
	raw, _ := job["steps"].([]any)
	steps := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		step, ok := item.(map[string]any)
		if ok {
			steps = append(steps, step)
		}
	}
	return steps
}

func jobMap(t *testing.T, wf map[string]any, name string) map[string]any {
	t.Helper()
	jobs, _ := wf["jobs"].(map[string]any)
	job, ok := jobs[name].(map[string]any)
	if !ok {
		t.Fatalf("missing job %s", name)
	}
	return job
}

func loadWorkflow(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wf map[string]any
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf["on"].(map[string]any); !ok {
		t.Fatalf("workflow %s did not decode the on: key as a mapping (%T)", path, wf["on"])
	}
	return wf
}

func nested(m map[string]any, keys ...string) any {
	var cur any = m
	for _, key := range keys {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = asMap[key]
	}
	return cur
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func stepLabel(step map[string]any) string {
	if name := asString(step["name"]); name != "" {
		return name
	}
	if id := asString(step["id"]); id != "" {
		return id
	}
	return asString(step["uses"])
}

func pathBase(value string) string {
	if i := strings.LastIndex(value, "/"); i >= 0 {
		return value[i+1:]
	}
	return value
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Dir(testdataDir(t))
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "testdata")
}

func truthy(v any) bool {
	switch typed := v.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	default:
		return true
	}
}

type token struct {
	kind string
	val  string
}

type exprParser struct {
	tokens []token
	pos    int
}

func evalExpr(input string, ctx map[string]any) (any, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "${{") && strings.HasSuffix(input, "}}") {
		input = strings.TrimSpace(input[3 : len(input)-2])
	}
	parser := &exprParser{tokens: lexExpr(input)}
	value, err := parser.parseOr(ctx)
	if err != nil {
		return nil, err
	}
	if parser.peek().kind != "eof" {
		return nil, fmt.Errorf("trailing %q in %s", parser.peek().val, input)
	}
	return value, nil
}

func (p *exprParser) parseOr(ctx map[string]any) (any, error) {
	left, err := p.parseAnd(ctx)
	if err != nil {
		return nil, err
	}
	for p.peek().val == "||" {
		p.pos++
		right, err := p.parseAnd(ctx)
		if err != nil {
			return nil, err
		}
		if truthy(left) {
			continue
		}
		left = right
	}
	return left, nil
}

func (p *exprParser) parseAnd(ctx map[string]any) (any, error) {
	left, err := p.parseCmp(ctx)
	if err != nil {
		return nil, err
	}
	for p.peek().val == "&&" {
		p.pos++
		right, err := p.parseCmp(ctx)
		if err != nil {
			return nil, err
		}
		if truthy(left) {
			left = right
		}
	}
	return left, nil
}

func (p *exprParser) parseCmp(ctx map[string]any) (any, error) {
	left, err := p.parseUnary(ctx)
	if err != nil {
		return nil, err
	}
	for p.peek().val == "==" || p.peek().val == "!=" {
		op := p.peek().val
		p.pos++
		right, err := p.parseUnary(ctx)
		if err != nil {
			return nil, err
		}
		same := equalValues(left, right)
		if op == "!=" {
			same = !same
		}
		left = same
	}
	return left, nil
}

func (p *exprParser) parseUnary(ctx map[string]any) (any, error) {
	if p.peek().val == "!" {
		p.pos++
		value, err := p.parseUnary(ctx)
		if err != nil {
			return nil, err
		}
		return !truthy(value), nil
	}
	return p.parsePrimary(ctx)
}

func (p *exprParser) parsePrimary(ctx map[string]any) (any, error) {
	current := p.peek()
	switch current.kind {
	case "punct":
		if current.val != "(" {
			return nil, fmt.Errorf("unexpected %s", current.val)
		}
		p.pos++
		value, err := p.parseOr(ctx)
		if err != nil {
			return nil, err
		}
		if p.peek().val != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return value, nil
	case "str", "num":
		p.pos++
		return current.val, nil
	case "ident":
		p.pos++
		if p.peek().val == "(" {
			p.pos++
			var args []any
			if p.peek().val != ")" {
				for {
					arg, err := p.parseOr(ctx)
					if err != nil {
						return nil, err
					}
					args = append(args, arg)
					if p.peek().val != "," {
						break
					}
					p.pos++
				}
			}
			if p.peek().val != ")" {
				return nil, fmt.Errorf("missing ) after %s", current.val)
			}
			p.pos++
			if current.val != "endsWith" || len(args) != 2 {
				return nil, fmt.Errorf("unsupported call %s", current.val)
			}
			return strings.HasSuffix(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
		}
		if current.val == "true" {
			return true, nil
		}
		if current.val == "false" {
			return false, nil
		}
		return lookup(ctx, current.val), nil
	default:
		return nil, fmt.Errorf("unexpected %s", current.val)
	}
}

func (p *exprParser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{kind: "eof"}
	}
	return p.tokens[p.pos]
}

func lexExpr(input string) []token {
	var tokens []token
	i := 0
	for i < len(input) {
		switch input[i] {
		case ' ', '\n', '\t', '\r':
			i++
		case '(', ')', ',':
			tokens = append(tokens, token{kind: "punct", val: input[i : i+1]})
			i++
		case '!':
			if i+1 < len(input) && input[i+1] == '=' {
				tokens = append(tokens, token{kind: "op", val: "!="})
				i += 2
				continue
			}
			tokens = append(tokens, token{kind: "op", val: "!"})
			i++
		case '=':
			if i+1 < len(input) && input[i+1] == '=' {
				tokens = append(tokens, token{kind: "op", val: "=="})
				i += 2
				continue
			}
			tokens = append(tokens, token{kind: "punct", val: "="})
			i++
		case '&':
			if i+1 < len(input) && input[i+1] == '&' {
				tokens = append(tokens, token{kind: "op", val: "&&"})
				i += 2
				continue
			}
			i++
		case '|':
			if i+1 < len(input) && input[i+1] == '|' {
				tokens = append(tokens, token{kind: "op", val: "||"})
				i += 2
				continue
			}
			i++
		case '\'':
			i++
			start := i
			for i < len(input) && input[i] != '\'' {
				i++
			}
			tokens = append(tokens, token{kind: "str", val: input[start:i]})
			if i < len(input) {
				i++
			}
		default:
			start := i
			for i < len(input) && isIdent(input[i]) {
				i++
			}
			if start == i {
				i++
				continue
			}
			word := input[start:i]
			kind := "ident"
			if regexp.MustCompile(`^[0-9]+$`).MatchString(word) {
				kind = "num"
			}
			tokens = append(tokens, token{kind: kind, val: word})
		}
	}
	return tokens
}

func isIdent(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.' || b == '-'
}

func lookup(ctx map[string]any, path string) any {
	var cur any = ctx
	for _, part := range strings.Split(path, ".") {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = asMap[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func equalValues(a, b any) bool {
	if ab, aok := a.(bool); aok {
		if bb, bok := b.(bool); bok {
			return ab == bb
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}
