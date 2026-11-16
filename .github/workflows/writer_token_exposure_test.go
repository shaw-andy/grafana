package workflows_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writerTokenPlaceholder is a stand-in for the installation token minted by
// create_token.sh. The test never uses a real credential.
const writerTokenPlaceholder = "WRITER_TOKEN_PLACEHOLDER"

// stepOutputExpr matches the steps-context lookup the runner evaluates for
// ${{ steps.<id>.outputs.<name> }}. Index.EvaluateCore returns the stored
// string unchanged.
var stepOutputExpr = regexp.MustCompile(`^\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}$`)

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string         `yaml:"name"`
	ID   string         `yaml:"id"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
	Run  string         `yaml:"run"`
}

type exposure struct {
	File    string
	Job     string
	Uses    string
	Ref     string
	Inputs  map[string]string
	StepEnv map[string]string
}

func TestGrafanaWriterTokenNotDeliveredToMovableAction(t *testing.T) {
	root := repoRoot(t)
	exposures := findWriterTokenExposures(t, root)
	if len(exposures) == 0 {
		return
	}

	coreDir := installActionsCore(t)
	sort.Slice(exposures, func(i, j int) bool {
		if exposures[i].File != exposures[j].File {
			return exposures[i].File < exposures[j].File
		}
		if exposures[i].Job != exposures[j].Job {
			return exposures[i].Job < exposures[j].Job
		}
		return exposures[i].Uses < exposures[j].Uses
	})

	for _, exp := range exposures {
		delivered := deliverTokenToAction(t, coreDir, exp)
		if delivered == writerTokenPlaceholder {
			t.Errorf("%s job %s passes the grafana-writer token to movable action %s (ref %q). The action read that token back through @actions/core getInput. persist-credentials=%q does not remove it from the action inputs.",
				exp.File, exp.Job, exp.Uses, exp.Ref, exp.Inputs["persist-credentials"])
		} else {
			t.Errorf("%s job %s is an exposure but the action input channel did not return the writer token (got %q)", exp.File, exp.Job, delivered)
		}
	}

	// The same minted value is what the workflow's own branch-cut and commit
	// steps present. A movable action that read it can repeat those calls.
	assertSameTokenCreatesRefs(t, root)
	assertSameTokenSelectsWorkflowFiles(t, root)
}

func findWriterTokenExposures(t *testing.T, root string) []exposure {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []exposure
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for jobName, job := range wf.Jobs {
			minted := mintedWriterTokenExprs(job.Steps)
			if len(minted) == 0 {
				continue
			}
			for _, step := range job.Steps {
				local, ref, ok := actionRef(step.Uses)
				if local || !ok || isFullCommitSHA(ref) {
					continue
				}
				inputs := evaluatedInputs(step.With, minted)
				env := evaluatedInputs(step.Env, minted)
				if !carriesWriterToken(inputs) && !carriesWriterToken(env) {
					continue
				}
				found = append(found, exposure{
					File:    name,
					Job:     jobName,
					Uses:    step.Uses,
					Ref:     ref,
					Inputs:  inputs,
					StepEnv: env,
				})
			}
		}
	}
	return found
}

func mintedWriterTokenExprs(steps []workflowStep) map[string]string {
	minted := map[string]string{}
	for _, step := range steps {
		if step.ID == "" || !strings.Contains(step.Uses, "create-github-app-token") {
			continue
		}
		if !stepMintsGrafanaWriter(steps, step) {
			continue
		}
		// create_token.sh writes github_token=<token> to GITHUB_OUTPUT.
		// The composite action's output "token" is
		// ${{ steps.generate-token.outputs.github_token }}.
		minted[step.ID] = writerTokenPlaceholder
	}
	return minted
}

func stepMintsGrafanaWriter(steps []workflowStep, step workflowStep) bool {
	app, ok := asString(step.With["github_app"])
	if !ok {
		return false
	}
	if strings.TrimSpace(app) == "grafana-writer" {
		return true
	}
	m := stepOutputExpr.FindStringSubmatch(strings.TrimSpace(app))
	if m == nil || m[2] != "github_app" {
		return false
	}
	for _, prev := range steps {
		if prev.ID == m[1] && strings.Contains(prev.Run, "app=grafana-writer") {
			return true
		}
	}
	return false
}

func evaluatedInputs(raw map[string]any, minted map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range raw {
		text, ok := asString(value)
		if !ok {
			continue
		}
		out[key] = evalWriterExpr(text, minted)
	}
	return out
}

func evalWriterExpr(text string, minted map[string]string) string {
	m := stepOutputExpr.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return text
	}
	if token, ok := minted[m[1]]; ok && m[2] == "token" {
		return token
	}
	return text
}

func carriesWriterToken(values map[string]string) bool {
	for _, value := range values {
		if value == writerTokenPlaceholder {
			return true
		}
	}
	return false
}

func actionRef(uses string) (local bool, ref string, ok bool) {
	uses = strings.TrimSpace(uses)
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return true, "", false
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return false, "", false
	}
	return false, uses[at+1:], true
}

func isFullCommitSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// deliverTokenToAction runs the runner's input path for one exposed step.
//
// create_token.sh appends github_token=<token> to GITHUB_OUTPUT.
// SetOutputFileCommand splits on the first '=' and stores the value.
// The composite output expression selects that value as outputs.token.
// ActionRunner.EvaluateStepInputs resolves the workflow's with: block to
// that string. Handler.AddInputsToEnvironment publishes INPUT_<NAME>, and
// NodeScriptActionHandler passes the dictionary to the action process.
// @actions/core getInput reads INPUT_TOKEN, which is what actions/checkout
// v5 does for its token input.
func deliverTokenToAction(t *testing.T, coreDir string, exp exposure) string {
	t.Helper()
	outputFile := filepath.Join(t.TempDir(), "github_output")
	line := "github_token=" + writerTokenPlaceholder + "\n"
	if err := os.WriteFile(outputFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := parseGitHubOutput(t, outputFile)
	if parsed["github_token"] != writerTokenPlaceholder {
		t.Fatalf("GITHUB_OUTPUT parse mismatch: %#v", parsed)
	}

	// Composite output token <- steps.generate-token.outputs.github_token.
	if parsed["github_token"] == "" {
		t.Fatal("minted token missing")
	}

	env := addInputsToEnvironment(exp.Inputs)
	// A composite action stores the same input dictionary and evaluates
	// ${{ inputs.token }} into a child step's environment.
	if childToken, ok := compositeChildToken(exp.Inputs); ok && childToken != writerTokenPlaceholder {
		t.Fatalf("composite inputs.token lookup returned %q", childToken)
	}

	script := filepath.Join(t.TempDir(), "read-input.js")
	if err := os.WriteFile(script, []byte(readInputJS), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", script)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + coreDir,
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("getInput: %v", err)
	}
	var got struct {
		Token    string `json:"token"`
		InputEnv string `json:"inputEnv"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("getInput output %q: %v", out, err)
	}
	if got.Error != "" {
		t.Fatalf("getInput error: %s", got.Error)
	}
	if got.Token != got.InputEnv {
		t.Fatalf("getInput %q disagrees with INPUT_TOKEN %q", got.Token, got.InputEnv)
	}
	return got.Token
}

const readInputJS = `
const core = require('@actions/core');
try {
  const token = core.getInput('token', {required: true});
  process.stdout.write(JSON.stringify({token: token, inputEnv: process.env.INPUT_TOKEN || ''}));
} catch (err) {
  process.stdout.write(JSON.stringify({error: String(err && err.message || err), inputEnv: process.env.INPUT_TOKEN || ''}));
}
`

// parseGitHubOutput implements the NAME=VALUE branch of EnvFileKeyValuePairs.
func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string]string{}
	for _, line := range strings.Split(string(text), "\n") {
		if line == "" {
			continue
		}
		equals := strings.Index(line, "=")
		heredoc := strings.Index(line, "<<")
		if equals >= 0 && (heredoc < 0 || equals < heredoc) {
			parts := strings.SplitN(line, "=", 2)
			parsed[parts[0]] = parts[1]
			continue
		}
		t.Fatalf("unsupported GITHUB_OUTPUT line %q", line)
	}
	return parsed
}

func addInputsToEnvironment(inputs map[string]string) map[string]string {
	env := map[string]string{}
	for key, value := range inputs {
		env["INPUT_"+strings.ToUpper(strings.ReplaceAll(key, " ", "_"))] = value
	}
	return env
}

func compositeChildToken(inputs map[string]string) (string, bool) {
	// CompositeActionHandler copies Inputs into the child expression context
	// under "inputs". ${{ inputs.token }} indexes that object.
	value, ok := inputs["token"]
	return value, ok
}

func assertSameTokenCreatesRefs(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ran bool
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatal(err)
		}
		for _, job := range wf.Jobs {
			minted := mintedWriterTokenExprs(job.Steps)
			for _, step := range job.Steps {
				token, ok := stepEnvToken(step, minted)
				if !ok || !strings.Contains(step.Run, "git/refs") || strings.Contains(step.Run, "jq ") {
					continue
				}
				ran = true
				seen := runRefCreation(t, step.Run, token)
				if seen != writerTokenPlaceholder {
					t.Errorf("%s ref creation presented %q", name, seen)
				}
			}
		}
	}
	if !ran {
		t.Error("no workflow step creates a git ref with the grafana-writer token")
	}
}

func stepEnvToken(step workflowStep, minted map[string]string) (string, bool) {
	for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		raw, ok := asString(step.Env[key])
		if !ok {
			continue
		}
		value := evalWriterExpr(raw, minted)
		if value == writerTokenPlaceholder {
			return value, true
		}
	}
	return "", false
}

func runRefCreation(t *testing.T, script string, token string) string {
	t.Helper()
	dir := t.TempDir()
	git := exec.Command("git", "init", "-q")
	git.Dir = dir
	if out, err := git.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README", "seed\n")
	commit := exec.Command("git", "add", "README")
	commit.Dir = dir
	commit.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	commit = exec.Command("git", "commit", "-q", "-m", "seed")
	commit.Dir = dir
	commit.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v %s", err, out)
	}
	for _, ref := range []string{"refs/remotes/origin/release-0.0.0", "refs/remotes/origin/main"} {
		update := exec.Command("git", "update-ref", ref, "HEAD")
		update.Dir = dir
		if out, err := update.CombinedOutput(); err != nil {
			t.Fatalf("update-ref %s: %v %s", ref, err, out)
		}
	}

	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	tokenOut := filepath.Join(dir, "token")
	argsOut := filepath.Join(dir, "args")
	stub := "#!/bin/sh\nprintf '%s' \"$GH_TOKEN\" > \"$TOKEN_OUT\"\nprintf '%s\\n' \"$@\" > \"$ARGS_OUT\"\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GH_TOKEN=" + token,
		"GITHUB_REPOSITORY=grafana/grafana",
		"RELEASE_BRANCH=release-0.0.0",
		"REF_NAME=main",
		"WORK_BRANCH=bump-version/0/0.0.0-pre",
		"TOKEN_OUT=" + tokenOut,
		"ARGS_OUT=" + argsOut,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ref script: %v %s", err, out)
	}
	seen, err := os.ReadFile(tokenOut)
	if err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "repos/grafana/grafana/git/refs") || !strings.Contains(string(args), "POST") {
		t.Fatalf("ref script did not call the git refs API: %s", args)
	}
	return string(seen)
}

func assertSameTokenSelectsWorkflowFiles(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var patterns []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatal(err)
		}
		for _, job := range wf.Jobs {
			minted := mintedWriterTokenExprs(job.Steps)
			for _, step := range job.Steps {
				token, ok := stepEnvToken(step, minted)
				if !ok || !strings.Contains(step.Uses, "ghcommit-action") {
					continue
				}
				pattern, ok := asString(step.With["file_pattern"])
				if !ok {
					t.Fatalf("%s ghcommit step has no file_pattern", name)
				}
				if token != writerTokenPlaceholder {
					t.Fatalf("%s ghcommit token %q", name, token)
				}
				patterns = append(patterns, pattern)
			}
		}
	}
	if len(patterns) == 0 {
		t.Error("no ghcommit step commits with the grafana-writer token")
		return
	}
	for _, pattern := range patterns {
		selected := gitStatusNames(t, pattern)
		if !containsWorkflowPath(selected) {
			t.Errorf("file_pattern %q did not select a workflow file: %v", pattern, selected)
		}
	}
}

func gitStatusNames(t *testing.T, pattern string) []string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	path := filepath.Join(dir, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "seed")
	if err := os.WriteFile(path, []byte("name: ci\nchanged: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// entrypoint.sh passes file_pattern to git status as a pathspec.
	cmd := exec.Command("git", "status", "-s", "--porcelain=v1", "-z", "--", pattern)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git status: %v", err)
	}
	var names []string
	for _, rec := range strings.Split(string(out), "\x00") {
		if len(rec) < 4 {
			continue
		}
		names = append(names, rec[3:])
	}
	return names
}

func containsWorkflowPath(names []string) bool {
	for _, name := range names {
		if strings.HasPrefix(name, ".github/workflows/") {
			return true
		}
	}
	return false
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v %s", strings.Join(args, " "), err, out)
	}
}

func installActionsCore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("npm", "install", "--silent", "--prefix", dir, "@actions/core@1.10.1")
	cmd.Env = append(os.Environ(), "npm_config_audit=false", "npm_config_fund=false")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("npm install @actions/core@1.10.1: %v %s", err, out)
	}
	return filepath.Join(dir, "node_modules")
}

func asString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	case int:
		return fmt.Sprintf("%d", typed), true
	case int64:
		return fmt.Sprintf("%d", typed), true
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed)), true
		}
		return fmt.Sprintf("%v", typed), true
	default:
		return "", false
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}
