package gha

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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests exercise the pull_request_target path in the repository workflows.
// A moving action ref is resolved the way actions/runner v2.338.2 asks GitHub to
// resolve it (the ref string is sent as ActionReference.Ref and the downloaded
// tree is the ResolvedSha). The job GITHUB_TOKEN is passed through as INPUT_*
// the way NodeScriptActionHandler does, and the mock API allows a call only when
// the token's permissions include that endpoint at the required access and the
// repository in the URL is the repository the token was minted for.

const (
	actionOwnerRepo = "grafana/grafana-github-actions"
	baseRepository  = "grafana/grafana"
	forkRepository  = "contributor/grafana"
	// Obvious placeholder. This is not a credential.
	jobTokenPlaceholder = "placeholder-job-token"
)

func TestForkPullRequestTargetMovingActionRefCannotMutateBaseRepository(t *testing.T) {
	root := repositoryRoot(t)
	for _, activity := range []string{"opened", "synchronize", "labeled"} {
		t.Run(activity, func(t *testing.T) {
			result := runWorkflows(t, root, activity)
			if result.movingRef && !result.attackRan {
				t.Fatalf("workflow still points a pull_request_target job at a moving action ref, but the harness did not execute it")
			}
			if writes := successfulMutations(result.mutations); len(writes) > 0 {
				t.Fatalf("fork pull_request_target %s let the action at the moving ref mutate the base repository with the job token:\n%s", activity, formatMutations(writes))
			}
		})
	}
}

func TestHarnessMovingRefReceivesJobToken(t *testing.T) {
	workflow := `
name: synthetic
on:
  pull_request_target:
    types: [opened, synchronize, labeled]
permissions: {}
jobs:
  main:
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: grafana/grafana-github-actions/commands@main
        with:
          token: ${{secrets.GITHUB_TOKEN}}
          configPath: pr-commands
`
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.yml")
	if err := os.WriteFile(path, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	result := runWorkflows(t, dir, "opened")
	if !result.attackRan {
		t.Fatal("harness did not run the action checked out at main")
	}
	if !sawMutation(result.mutations, "POST", "/repos/"+baseRepository+"/issues/4242/comments") {
		t.Fatalf("expected issue comment on the base repository, got:\n%s", formatMutations(result.mutations))
	}
	if !sawMutation(result.mutations, "POST", "/repos/"+baseRepository+"/pulls/4242/reviews") {
		t.Fatalf("expected pull request review on the base repository, got:\n%s", formatMutations(result.mutations))
	}
	if !sawMutation(result.mutations, "POST", "/repos/"+baseRepository+"/issues/4242/labels") {
		t.Fatalf("expected label write on the base repository, got:\n%s", formatMutations(result.mutations))
	}
	for _, mutation := range result.mutations {
		if mutation.Status < 200 || mutation.Status >= 300 {
			continue
		}
		if mutation.Repository != baseRepository {
			t.Fatalf("job token mutated %s; it is minted for %s", mutation.Repository, baseRepository)
		}
		if mutation.Token != jobTokenPlaceholder {
			t.Fatalf("mutation used token %q, want the job token placeholder", mutation.Token)
		}
	}
	if sawMutation(result.mutations, "PUT", "/repos/"+baseRepository+"/contents/README.md") {
		t.Fatal("contents: read token was allowed to write repository contents")
	}
	if sawMutation(result.mutations, "POST", "/repos/"+forkRepository+"/issues/4242/comments") {
		t.Fatal("job token was accepted for the fork repository")
	}
}

func TestHarnessOmittedTokenInputUsesGitHubTokenDefault(t *testing.T) {
	workflow := `
name: synthetic
on:
  pull_request_target:
    types: [opened]
permissions: {}
jobs:
  main:
    permissions:
      pull-requests: write
      issues: write
    steps:
      - uses: grafana/grafana-github-actions/commands@main
        with:
          configPath: pr-commands
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default-token.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	result := runWorkflows(t, dir, "opened")
	if !sawMutation(result.mutations, "POST", "/repos/"+baseRepository+"/issues/4242/comments") {
		t.Fatalf("action default github.token did not authorize an issue comment:\n%s", formatMutations(result.mutations))
	}
}

func TestHarnessPinnedSHAIgnoresLaterMain(t *testing.T) {
	fixture := newActionFixture(t)
	workflow := fmt.Sprintf(`
name: synthetic
on:
  pull_request_target:
    types: [opened]
permissions: {}
jobs:
  main:
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: grafana/grafana-github-actions/commands@%s
        with:
          token: ${{secrets.GITHUB_TOKEN}}
          configPath: pr-commands
`, fixture.benignSHA)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pinned.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	result := runWorkflowsWithFixture(t, dir, "opened", fixture)
	if result.attackRan {
		t.Fatalf("pinned SHA %s executed the commit later pushed to main (%s)", fixture.benignSHA, fixture.attackSHA)
	}
	if len(result.mutations) != 0 {
		t.Fatalf("pinned action mutated the base repository:\n%s", formatMutations(result.mutations))
	}
	if result.selectedSHA != fixture.benignSHA {
		t.Fatalf("selected SHA %s, want pinned %s", result.selectedSHA, fixture.benignSHA)
	}
}

type mutation struct {
	Method     string
	Path       string
	Repository string
	Status     int
	Token      string
}

type runResult struct {
	mutations   []mutation
	attackRan   bool
	movingRef   bool
	selectedSHA string
}

func successfulMutations(mutations []mutation) []mutation {
	var writes []mutation
	for _, mutation := range mutations {
		if mutation.Status >= 200 && mutation.Status < 300 {
			writes = append(writes, mutation)
		}
	}
	return writes
}

func sawMutation(mutations []mutation, method, path string) bool {
	for _, mutation := range mutations {
		if mutation.Method == method && mutation.Path == path && mutation.Status >= 200 && mutation.Status < 300 {
			return true
		}
	}
	return false
}

func formatMutations(mutations []mutation) string {
	var buf strings.Builder
	for _, mutation := range mutations {
		fmt.Fprintf(&buf, "%s %s -> %d token=%s\n", mutation.Method, mutation.Path, mutation.Status, mutation.Token)
	}
	return buf.String()
}

func runWorkflows(t *testing.T, workflowsDir string, activity string) runResult {
	t.Helper()
	return runWorkflowsWithFixture(t, workflowsDir, activity, newActionFixture(t))
}

func runWorkflowsWithFixture(t *testing.T, workflowsDir string, activity string, fixture actionFixture) runResult {
	t.Helper()
	workflows := loadWorkflows(t, workflowsDir)
	event := forkPullRequestEvent(activity)
	var result runResult
	for _, workflow := range workflows {
		for _, job := range workflow.jobs {
			if !job.triggers(activity) {
				continue
			}
			permissions := job.permissions
			token := mintedToken{value: jobTokenPlaceholder, repository: baseRepository, permissions: permissions}
			for _, step := range job.steps {
				if step.uses.ownerRepo != actionOwnerRepo {
					continue
				}
				selected := resolveActionRef(t, fixture, step.uses.ref)
				result.selectedSHA = selected
				if !fullSHA.MatchString(step.uses.ref) {
					result.movingRef = true
				}
				if selected != fixture.attackSHA {
					continue
				}
				result.attackRan = true
				result.mutations = append(result.mutations, executeAction(t, fixture, selected, step, token, event)...)
			}
		}
	}
	return result
}

type mintedToken struct {
	value       string
	repository  string
	permissions map[string]string
}

type actionFixture struct {
	dir       string
	benignSHA string
	attackSHA string
}

func newActionFixture(t *testing.T) actionFixture {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Fixture",
			"GIT_AUTHOR_EMAIL=fixture@example.com",
			"GIT_COMMITTER_NAME=Fixture",
			"GIT_COMMITTER_EMAIL=fixture@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-b", "main")
	writeActionTree(t, dir, benignScript)
	git("add", ".")
	git("commit", "-m", "benign action")
	benign := git("rev-parse", "HEAD")
	writeActionTree(t, dir, attackScript)
	git("add", ".")
	git("commit", "-m", "attacker updates main")
	attack := git("rev-parse", "HEAD")
	return actionFixture{dir: dir, benignSHA: benign, attackSHA: attack}
}

func writeActionTree(t *testing.T, repo, script string) {
	t.Helper()
	actionDir := filepath.Join(repo, "commands")
	if err := os.MkdirAll(filepath.Join(actionDir, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	actionYAML := `name: Commands
description: test fixture
inputs:
  token:
    description: GitHub token
    default: ${{ github.token }}
  configPath:
    description: config
    required: true
runs:
  using: node24
  main: dist/index.js
`
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actionDir, "dist", "index.js"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
}

const benignScript = `
process.exit(0);
`

const attackScript = `
const http = require('http');
const fs = require('fs');
const token = process.env.INPUT_TOKEN || '';
const api = process.env.GITHUB_API_URL;
const repo = process.env.GITHUB_REPOSITORY;
const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
const number = event.pull_request.number;
const fork = event.pull_request.head.repo.full_name;

function call(method, path, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const url = new URL(api + path);
    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      agent: false,
      headers: {
        'authorization': 'Bearer ' + token,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'connection': 'close',
      },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', () => resolve(0));
    req.write(payload);
    req.end();
  });
}

(async () => {
  await call('POST', '/repos/' + repo + '/issues/' + number + '/comments', {body: 'posted as the workflow token'});
  await call('POST', '/repos/' + repo + '/pulls/' + number + '/reviews', {body: 'review as the workflow token', event: 'COMMENT'});
  await call('POST', '/repos/' + repo + '/issues/' + number + '/labels', {labels: ['needs-attention']});
  await call('PUT', '/repos/' + repo + '/contents/README.md', {message: 'contents write', content: 'eA=='});
  await call('POST', '/repos/' + fork + '/issues/' + number + '/comments', {body: 'fork write'});
  process.exit(0);
})();
`

func resolveActionRef(t *testing.T, fixture actionFixture, ref string) string {
	t.Helper()
	if fullSHA.MatchString(ref) {
		return ref
	}
	// A branch or tag is resolved when the job runs. Someone who can update that
	// ref can move it onto the commit currently at main after review.
	update := exec.Command("git", "update-ref", "refs/heads/"+ref, fixture.attackSHA)
	update.Dir = fixture.dir
	if out, err := update.CombinedOutput(); err != nil {
		t.Fatalf("update ref %s: %v\n%s", ref, err, out)
	}
	resolve := exec.Command("git", "rev-parse", "refs/heads/"+ref)
	resolve.Dir = fixture.dir
	out, err := resolve.CombinedOutput()
	if err != nil {
		t.Fatalf("rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func executeAction(t *testing.T, fixture actionFixture, sha string, step parsedStep, token mintedToken, event map[string]any) []mutation {
	t.Helper()
	checkout := t.TempDir()
	archive := exec.Command("git", "archive", sha)
	archive.Dir = fixture.dir
	tar := exec.Command("tar", "-x", "-C", checkout)
	var archiveErr bytes.Buffer
	archive.Stderr = &archiveErr
	stdout, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	tar.Stdin = stdout
	var tarErr bytes.Buffer
	tar.Stderr = &tarErr
	if err := tar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Wait(); err != nil {
		t.Fatalf("git archive %s: %v\n%s", sha, err, archiveErr.String())
	}
	if err := tar.Wait(); err != nil {
		t.Fatalf("tar: %v\n%s", err, tarErr.String())
	}

	actionDir := checkout
	if step.uses.path != "" {
		actionDir = filepath.Join(checkout, filepath.FromSlash(step.uses.path))
	}
	manifest := readActionManifest(t, actionDir)
	inputs := map[string]string{}
	for name, spec := range manifest.inputs {
		if spec.def != "" {
			inputs[name] = evalExpression(spec.def, token)
		}
	}
	for name, value := range step.with {
		inputs[name] = evalExpression(value, token)
	}

	eventDir := t.TempDir()
	eventPath := filepath.Join(eventDir, "event.json")
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	var mutations []mutation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = body
		status, repository := authorize(r, token)
		header := r.Header.Get("Authorization")
		got := strings.TrimPrefix(header, "Bearer ")
		mutations = append(mutations, mutation{
			Method:     r.Method,
			Path:       r.URL.Path,
			Repository: repository,
			Status:     status,
			Token:      got,
		})
		w.WriteHeader(status)
	}))
	defer server.Close()

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"INPUT_TOKEN=" + inputs["token"],
		"INPUT_CONFIGPATH=" + inputs["configPath"],
		"GITHUB_API_URL=" + server.URL,
		"GITHUB_REPOSITORY=" + baseRepository,
		"GITHUB_EVENT_NAME=pull_request_target",
		"GITHUB_EVENT_PATH=" + eventPath,
	}
	script := filepath.Join(actionDir, filepath.FromSlash(manifest.main))
	cmd := exec.Command("node", script)
	cmd.Dir = actionDir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node %s: %v\n%s", script, err, out)
	}
	return mutations
}

type actionManifest struct {
	inputs map[string]inputSpec
	main   string
}

type inputSpec struct {
	def string
}

func readActionManifest(t *testing.T, actionDir string) actionManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(actionDir, "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	manifest := actionManifest{inputs: map[string]inputSpec{}}
	if runs, ok := doc["runs"].(map[string]any); ok {
		manifest.main, _ = runs["main"].(string)
	}
	if inputs, ok := doc["inputs"].(map[string]any); ok {
		for name, rawSpec := range inputs {
			spec, _ := rawSpec.(map[string]any)
			def, _ := spec["default"].(string)
			manifest.inputs[name] = inputSpec{def: def}
		}
	}
	if manifest.main == "" {
		t.Fatal("action.yml has no runs.main")
	}
	return manifest
}

func evalExpression(value string, token mintedToken) string {
	return expression.ReplaceAllStringFunc(value, func(match string) string {
		inner := strings.TrimSpace(expression.FindStringSubmatch(match)[1])
		switch inner {
		case "secrets.GITHUB_TOKEN", "github.token":
			return token.value
		default:
			return match
		}
	})
}

var expression = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

func authorize(r *http.Request, token mintedToken) (int, string) {
	header := r.Header.Get("Authorization")
	got := strings.TrimPrefix(header, "Bearer ")
	if got == header || got != token.value {
		return http.StatusUnauthorized, ""
	}
	repository, ok := repositoryFromPath(r.URL.Path)
	if !ok {
		return http.StatusNotFound, ""
	}
	if repository != token.repository {
		return http.StatusForbidden, repository
	}
	needed := permissionFor(r.Method, r.URL.Path)
	if len(needed) == 0 {
		return http.StatusForbidden, repository
	}
	for _, permission := range needed {
		if token.permissions[permission] == "write" {
			return http.StatusCreated, repository
		}
	}
	return http.StatusForbidden, repository
}

func repositoryFromPath(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "repos" {
		return "", false
	}
	return parts[1] + "/" + parts[2], true
}

// permissionFor reports the repository permission keys that grant the call.
// The endpoint list is the server-to-server map in
// github/docs src/github-apps/data/fpt-2026-03-10/server-to-server-permissions.json
// at d59b2631959db46d71ca5f7748ec04311c6d0870. GITHUB_TOKEN permission names are
// the ones the workflow syntax uses for those same GitHub App permissions.
func permissionFor(method, path string) []string {
	switch {
	case method == http.MethodPost && matchPath(path, "/repos/*/*/issues/*/comments"):
		return []string{"issues", "pull-requests"}
	case method == http.MethodPost && matchPath(path, "/repos/*/*/issues/*/labels"):
		return []string{"issues", "pull-requests"}
	case method == http.MethodPost && matchPath(path, "/repos/*/*/pulls/*/reviews"):
		return []string{"pull-requests"}
	case method == http.MethodPut && matchPath(path, "/repos/*/*/contents/*"):
		return []string{"contents"}
	default:
		return nil
	}
}

func matchPath(path, pattern string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	want := strings.Split(strings.Trim(pattern, "/"), "/")
	if len(parts) != len(want) {
		return false
	}
	for i := range want {
		if want[i] == "*" {
			continue
		}
		if parts[i] != want[i] {
			return false
		}
	}
	return true
}

type parsedWorkflow struct {
	jobs []parsedJob
}

type parsedJob struct {
	permissions map[string]string
	types       []string
	steps       []parsedStep
}

func (j parsedJob) triggers(activity string) bool {
	if len(j.types) == 0 {
		return false
	}
	for _, kind := range j.types {
		if kind == activity {
			return true
		}
	}
	return false
}

type parsedStep struct {
	uses actionUses
	with map[string]string
}

type actionUses struct {
	ownerRepo string
	path      string
	ref       string
}

func loadWorkflows(t *testing.T, dir string) []parsedWorkflow {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{dir}
	if info.IsDir() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		paths = nil
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
				paths = append(paths, filepath.Join(dir, name))
			}
		}
	}
	var workflows []parsedWorkflow
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		workflows = append(workflows, parseWorkflow(t, raw))
	}
	return workflows
}

func parseWorkflow(t *testing.T, raw []byte) parsedWorkflow {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	on, ok := doc["on"].(map[string]any)
	if !ok {
		return parsedWorkflow{}
	}
	target, ok := on["pull_request_target"]
	if !ok {
		return parsedWorkflow{}
	}
	types := activityTypes(target)
	workflowPerms := parsePermissions(doc["permissions"])
	jobsRaw, _ := doc["jobs"].(map[string]any)
	var jobs []parsedJob
	for _, rawJob := range jobsRaw {
		jobMap, ok := rawJob.(map[string]any)
		if !ok {
			continue
		}
		perms := workflowPerms
		if _, present := jobMap["permissions"]; present {
			perms = parsePermissions(jobMap["permissions"])
		}
		var steps []parsedStep
		stepList, _ := jobMap["steps"].([]any)
		for _, rawStep := range stepList {
			stepMap, ok := rawStep.(map[string]any)
			if !ok {
				continue
			}
			usesText, _ := stepMap["uses"].(string)
			uses, ok := parseUses(usesText)
			if !ok {
				continue
			}
			with := map[string]string{}
			if withMap, ok := stepMap["with"].(map[string]any); ok {
				for key, value := range withMap {
					with[key], _ = value.(string)
				}
			}
			steps = append(steps, parsedStep{uses: uses, with: with})
		}
		if len(steps) == 0 {
			continue
		}
		jobs = append(jobs, parsedJob{permissions: perms, types: types, steps: steps})
	}
	return parsedWorkflow{jobs: jobs}
}

func activityTypes(target any) []string {
	switch typed := target.(type) {
	case map[string]any:
		if raw, ok := typed["types"]; ok {
			return stringList(raw)
		}
	}
	return []string{"opened", "synchronize", "reopened"}
}

func stringList(raw any) []string {
	switch typed := raw.(type) {
	case []any:
		var out []string
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case string:
		return []string{typed}
	default:
		return nil
	}
}

func parsePermissions(raw any) map[string]string {
	switch typed := raw.(type) {
	case string:
		switch typed {
		case "read-all":
			return map[string]string{"contents": "read", "issues": "read", "pull-requests": "read"}
		case "write-all":
			return map[string]string{"contents": "write", "issues": "write", "pull-requests": "write"}
		default:
			return map[string]string{}
		}
	case map[string]any:
		out := map[string]string{}
		for key, value := range typed {
			text, _ := value.(string)
			out[key] = text
		}
		return out
	default:
		return map[string]string{}
	}
}

func parseUses(uses string) (actionUses, bool) {
	if uses == "" || strings.HasPrefix(uses, "docker://") || strings.HasPrefix(uses, "./") {
		return actionUses{}, false
	}
	segments := strings.Split(uses, "@")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return actionUses{}, false
	}
	pathSegments := strings.FieldsFunc(segments[0], func(r rune) bool { return r == '/' || r == '\\' })
	if len(pathSegments) < 2 {
		return actionUses{}, false
	}
	parsed := actionUses{
		ownerRepo: pathSegments[0] + "/" + pathSegments[1],
		ref:       segments[1],
	}
	if len(pathSegments) > 2 {
		parsed.path = strings.Join(pathSegments[2:], "/")
	}
	return parsed, true
}

func forkPullRequestEvent(activity string) map[string]any {
	return map[string]any{
		"action": activity,
		"number": 4242,
		"repository": map[string]any{
			"full_name": baseRepository,
		},
		"pull_request": map[string]any{
			"number": 4242,
			"head": map[string]any{
				"ref": "feature",
				"sha": "1111111111111111111111111111111111111111",
				"repo": map[string]any{
					"full_name": forkRepository,
					"fork":      true,
				},
			},
			"base": map[string]any{
				"ref": "main",
				"repo": map[string]any{
					"full_name": baseRepository,
				},
			},
		},
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, ".github", "workflows")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root")
		}
		dir = parent
	}
}
