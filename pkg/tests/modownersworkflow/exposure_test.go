package modownersworkflow

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// automationToken is a stand-in for the grafana-pr-automation installation token
// the workflow reads from steps.get-github-app-token.outputs.token. It is not a credential.
const automationToken = "placeholder-grafana-pr-automation-token"

const repository = "example/grafana"

// TestPullRequestCodeDoesNotObserveAutomationToken runs the Modowners reviewers
// workflow the way a pull_request job does: path filter, same-repository guard,
// checkout of the merge commit, then the step shell. The program from the pull
// request must not observe the automation token.
func TestPullRequestCodeDoesNotObserveAutomationToken(t *testing.T) {
	repo := repoRoot(t)
	workflowPath := filepath.Join(repo, ".github", "workflows", "modowners-reviewers.yml")
	modownersDir := filepath.Join(repo, "scripts", "modowners")

	cases := []struct {
		name     string
		headRepo string
		changes  []string
	}{
		{
			name:     "same-repository branch replaces scripts/modowners",
			headRepo: repository,
			changes:  []string{"scripts/modowners/modowners.go"},
		},
		{
			name:     "same-repository branch also changes go.mod",
			headRepo: repository,
			changes:  []string{"scripts/modowners/modowners.go", "go.mod"},
		},
		{
			name:     "same-repository branch also changes the workflow file",
			headRepo: repository,
			changes:  []string{"scripts/modowners/modowners.go", ".github/workflows/modowners-reviewers.yml"},
		},
		{
			name:     "fork branch replaces scripts/modowners",
			headRepo: "example-fork/grafana",
			changes:  []string{"scripts/modowners/modowners.go"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := executeWorkflow(t, workflowPath, modownersDir, tc.headRepo, tc.changes)
			if bytes.Contains(result.program, []byte(automationToken)) {
				t.Errorf("scripts/modowners/modowners.go from the pull request observed the grafana-pr-automation token")
			}
			if bytes.Contains(result.stepOutput, []byte(automationToken)) {
				t.Errorf("workflow step output contained the grafana-pr-automation token")
			}
			if bytes.Contains(result.gitConfig, []byte(automationToken)) {
				t.Errorf("checkout git config contained the grafana-pr-automation token")
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "modowners-reviewers.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("workflow file not found from working directory")
		}
		dir = parent
	}
}

type workflowFile struct {
	On struct {
		PullRequest struct {
			Paths       []string `yaml:"paths"`
			PathsIgnore []string `yaml:"paths-ignore"`
		} `yaml:"pull_request"`
	} `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	If    string         `yaml:"if"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	Env  map[string]string `yaml:"env"`
	With looseMap          `yaml:"with"`
}

// looseMap accepts workflow mappings whose values are strings or booleans.
type looseMap map[string]string

func (m *looseMap) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("mapping expected, got kind %d", n.Kind)
	}
	out := make(looseMap, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1].Value
	}
	*m = out
	return nil
}

type pullRequestEvent struct {
	headRepo string
	number   string
	baseRef  string
	headRef  string
	baseSHA  string
	headSHA  string
	mergeSHA string
	mergeRef string
	changed  []string
}

func (e pullRequestEvent) lookup(expr string) (string, bool) {
	switch strings.TrimSpace(expr) {
	case "github.repository":
		return repository, true
	case "github.ref":
		return e.mergeRef, true
	case "github.sha":
		return e.mergeSHA, true
	case "github.event.pull_request.number":
		return e.number, true
	case "github.event.pull_request.base.sha":
		return e.baseSHA, true
	case "github.event.pull_request.base.ref":
		return e.baseRef, true
	case "github.event.pull_request.head.sha":
		return e.headSHA, true
	case "github.event.pull_request.head.ref":
		return e.headRef, true
	case "github.event.pull_request.head.repo.full_name":
		return e.headRepo, true
	default:
		return "", false
	}
}

type executionResult struct {
	program    []byte
	stepOutput []byte
	gitConfig  []byte
}

func executeWorkflow(t *testing.T, workflowPath, modownersDir, headRepo string, extra []string) executionResult {
	t.Helper()
	wf := loadWorkflow(t, workflowPath)
	job, ok := wf.Jobs["request"]
	if !ok {
		t.Fatal("request job is missing")
	}

	sink := filepath.Join(t.TempDir(), "observed")
	fixture := buildFixture(t, modownersDir, sink, extra)
	event := pullRequestEvent{
		headRepo: headRepo,
		number:   "17",
		baseRef:  "main",
		headRef:  "topic",
		baseSHA:  fixture.baseSHA,
		headSHA:  fixture.headSHA,
		mergeSHA: fixture.mergeSHA,
		mergeRef: "refs/pull/17/merge",
		changed:  fixture.changed,
	}

	if !jobRuns(t, wf, job, event) {
		return executionResult{}
	}

	workspace := filepath.Join(t.TempDir(), "workspace")
	outputs := map[string]map[string]string{}
	var result executionResult

	for i, step := range job.Steps {
		if !evalIf(step.If, event, outputs) {
			continue
		}
		switch {
		case step.Uses != "" && strings.Contains(step.Uses, "create-github-app-token"):
			if step.With["github_app"] == "grafana-pr-automation" && step.ID != "" {
				outputs[step.ID] = map[string]string{"token": automationToken}
			}
		case strings.HasPrefix(step.Uses, "actions/checkout"):
			commit := checkoutCommit(step.With["ref"], event, outputs)
			dest := workspace
			if rel := step.With["path"]; rel != "" && rel != "." {
				dest = filepath.Join(workspace, rel)
			}
			var sparse []string
			if pattern := step.With["sparse-checkout"]; pattern != "" {
				sparse = strings.Split(pattern, "\n")
			}
			cone := step.With["sparse-checkout-cone-mode"] != "false"
			materialize(t, fixture.repo, dest, commit, sparse, cone)
			result.gitConfig = append(result.gitConfig, readGitConfig(dest)...)
		case strings.HasPrefix(step.Uses, "./"):
			result.stepOutput = append(result.stepOutput, runLocalAction(t, workspace, step, event, outputs)...)
		case step.Run != "":
			script := interpolate(step.Run, event, outputs)
			env := stepEnvironment(step.Env, event, outputs)
			out := runBash(t, workspace, script, env)
			result.stepOutput = append(result.stepOutput, out...)
			if file, err := os.ReadFile(sink); err == nil {
				result.program = append(result.program, file...)
			}
		default:
			t.Logf("step %d (%s) has no executable action", i, step.Name)
		}
	}
	return result
}

func loadWorkflow(t *testing.T, path string) workflowFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// gopkg.in/yaml.v3 resolves a bare "on" key as boolean true. Quote the trigger key.
	data = bytes.Replace(data, []byte("\non:"), []byte("\n\"on\":"), 1)
	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	return wf
}

func jobRuns(t *testing.T, wf workflowFile, job workflowJob, event pullRequestEvent) bool {
	t.Helper()
	if !evalIf(job.If, event, nil) {
		return false
	}
	paths := wf.On.PullRequest.Paths
	if len(paths) == 0 && len(wf.On.PullRequest.PathsIgnore) == 0 {
		return true
	}
	for _, file := range event.changed {
		ignored := false
		for _, pattern := range wf.On.PullRequest.PathsIgnore {
			if globMatch(pattern, file) {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}
		if len(paths) == 0 {
			return true
		}
		for _, pattern := range paths {
			if globMatch(pattern, file) {
				return true
			}
		}
	}
	return false
}

func evalIf(expr string, event pullRequestEvent, outputs map[string]map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}
	expr = strings.TrimSpace(unwrap(expr))
	if parts := strings.Split(expr, "||"); len(parts) > 1 {
		for _, part := range parts {
			if evalIf(part, event, outputs) {
				return true
			}
		}
		return false
	}
	if parts := strings.Split(expr, "&&"); len(parts) > 1 {
		for _, part := range parts {
			if !evalIf(part, event, outputs) {
				return false
			}
		}
		return true
	}
	op := ""
	var parts []string
	switch {
	case strings.Contains(expr, "!="):
		parts = strings.SplitN(expr, "!=", 2)
		op = "!="
	case strings.Contains(expr, "=="):
		parts = strings.SplitN(expr, "==", 2)
		op = "=="
	default:
		// Unknown conditions still run, so a token handed to pull request code is observed.
		return true
	}
	left, lok := resolve(strings.TrimSpace(parts[0]), event, outputs)
	right, rok := resolve(strings.TrimSpace(parts[1]), event, outputs)
	if !lok || !rok {
		return true
	}
	if op == "!=" {
		return left != right
	}
	return left == right
}

var exprPattern = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

func unwrap(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		return strings.TrimSpace(s[3 : len(s)-2])
	}
	return s
}

func interpolate(s string, event pullRequestEvent, outputs map[string]map[string]string) string {
	return exprPattern.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(match[3 : len(match)-2])
		value, ok := resolve(inner, event, outputs)
		if !ok {
			return match
		}
		return value
	})
}

func resolve(expr string, event pullRequestEvent, outputs map[string]map[string]string) (string, bool) {
	expr = strings.TrimSpace(strings.Trim(expr, "\"'"))
	if value, ok := event.lookup(expr); ok {
		return value, true
	}
	if rest, ok := strings.CutPrefix(expr, "steps."); ok {
		id, field, found := strings.Cut(rest, ".outputs.")
		if !found {
			return "", false
		}
		if out := outputs[id]; out != nil {
			value, ok := out[field]
			return value, ok
		}
		return "", false
	}
	if strings.HasPrefix(expr, "github.") || strings.HasPrefix(expr, "steps.") || strings.Contains(expr, "(") {
		return "", false
	}
	return expr, true
}

func stepEnvironment(declared map[string]string, event pullRequestEvent, outputs map[string]map[string]string) []string {
	env := map[string]string{
		"PATH":              os.Getenv("PATH"),
		"HOME":              os.Getenv("HOME"),
		"TMPDIR":            os.TempDir(),
		"GITHUB_REPOSITORY": repository,
		"GITHUB_REF":        event.mergeRef,
		"GITHUB_SHA":        event.mergeSHA,
		"GITHUB_WORKSPACE":  "",
	}
	for key, value := range declared {
		env[key] = interpolate(value, event, outputs)
	}
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	return out
}

// checkoutCommit is the commit actions/checkout selects for this pull_request.
// An empty ref uses GITHUB_REF and GITHUB_SHA, which for pull_request is the
// merge commit. An unrecognized ref also stays on that merge commit.
func checkoutCommit(refExpr string, event pullRequestEvent, outputs map[string]map[string]string) string {
	ref := strings.TrimSpace(interpolate(refExpr, event, outputs))
	switch ref {
	case "", event.mergeRef, event.mergeSHA:
		return event.mergeSHA
	case event.baseSHA, event.baseRef, "refs/heads/" + event.baseRef:
		return event.baseSHA
	case event.headSHA, event.headRef, "refs/heads/" + event.headRef:
		return event.headSHA
	default:
		return event.mergeSHA
	}
}

type fixture struct {
	repo     string
	baseSHA  string
	headSHA  string
	mergeSHA string
	changed  []string
}

func buildFixture(t *testing.T, modownersDir, sink string, extra []string) fixture {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "fixture")
	git(t, "", "git", "init", "-b", "main", repo)
	git(t, repo, "git", "config", "user.email", "dev@example.com")
	git(t, repo, "git", "config", "user.name", "Dev")
	writeFile(t, filepath.Join(repo, "scripts", "modowners", "go.mod"), mustRead(t, filepath.Join(modownersDir, "go.mod")))
	writeFile(t, filepath.Join(repo, "scripts", "modowners", "go.sum"), mustRead(t, filepath.Join(modownersDir, "go.sum")))
	writeFile(t, filepath.Join(repo, "scripts", "modowners", "modowners.go"), "package main\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(repo, "go.mod"), "module example\n\ngo 1.26.6\n")
	commitAll(t, repo, "base")
	base := revParse(t, repo, "HEAD")

	git(t, repo, "git", "checkout", "-b", "topic")
	writeFile(t, filepath.Join(repo, "scripts", "modowners", "modowners.go"), probeSource(sink))
	for _, path := range extra {
		if path == "scripts/modowners/modowners.go" {
			continue
		}
		// Keep the file valid. Replacing go.mod with arbitrary text stops `go run`
		// before the pull request program starts, which would hide the token leak.
		appendFile(t, filepath.Join(repo, path), "\n// pull request\n")
	}
	commitAll(t, repo, "head")
	head := revParse(t, repo, "HEAD")

	git(t, repo, "git", "checkout", "main")
	git(t, repo, "git", "merge", "--no-ff", "topic", "-m", fmt.Sprintf("Merge %s into %s", head, base))
	merge := revParse(t, repo, "HEAD")
	changed := splitLines(gitOutput(t, repo, "git", "diff", "--name-only", base, head))
	return fixture{repo: repo, baseSHA: base, headSHA: head, mergeSHA: merge, changed: changed}
}

func probeSource(sink string) string {
	return fmt.Sprintf(`package main

import (
	"os"
	"strings"
)

func main() {
	var b strings.Builder
	for _, env := range os.Environ() {
		b.WriteString(env)
		b.WriteByte('\n')
	}
	b.WriteString("args:\n")
	b.WriteString(strings.Join(os.Args, "\n"))
	if config, err := os.ReadFile(".git/config"); err == nil {
		b.Write(config)
	}
	_ = os.WriteFile(%q, []byte(b.String()), 0o600)
}
`, sink)
}

func materialize(t *testing.T, repo, dest, commit string, sparse []string, cone bool) {
	t.Helper()
	if err := os.RemoveAll(dest); err != nil {
		t.Fatal(err)
	}
	git(t, "", "git", "clone", "--shared", repo, dest)
	if len(sparse) > 0 {
		if cone {
			git(t, dest, "git", "sparse-checkout", "init", "--cone")
		} else {
			git(t, dest, "git", "sparse-checkout", "init", "--no-cone")
		}
		args := append([]string{"sparse-checkout", "set", "--"}, sparse...)
		git(t, dest, "git", args...)
	}
	git(t, dest, "git", "checkout", "--force", commit)
}

func runLocalAction(t *testing.T, workspace string, step workflowStep, event pullRequestEvent, outputs map[string]map[string]string) []byte {
	t.Helper()
	uses := strings.TrimPrefix(step.Uses, "./")
	actionPath := filepath.Join(workspace, uses, "action.yml")
	if _, err := os.Stat(actionPath); err != nil {
		actionPath = filepath.Join(workspace, uses, "action.yaml")
	}
	data, err := os.ReadFile(actionPath)
	if err != nil {
		// The pull request replaced the action with something this checkout does not contain.
		// Inputs that carry the automation token are already visible to that code.
		return tokenFromStepInputs(step, event, outputs)
	}
	var action struct {
		Runs struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatalf("parse %s: %v", actionPath, err)
	}
	var observed bytes.Buffer
	observed.Write(tokenFromStepInputs(step, event, outputs))
	for _, embedded := range action.Runs.Steps {
		if embedded.Run == "" || !evalIf(embedded.If, event, outputs) {
			continue
		}
		env := map[string]string{}
		for key, value := range step.Env {
			env[key] = value
		}
		for key, value := range embedded.Env {
			env[key] = interpolateInputs(value, step.With, event, outputs)
		}
		script := interpolateInputs(embedded.Run, step.With, event, outputs)
		out := runBash(t, workspace, script, stepEnvironment(env, event, outputs))
		observed.Write(out)
	}
	return observed.Bytes()
}

func tokenFromStepInputs(step workflowStep, event pullRequestEvent, outputs map[string]map[string]string) []byte {
	var b bytes.Buffer
	for _, value := range step.With {
		resolved := interpolate(value, event, outputs)
		if strings.Contains(resolved, automationToken) {
			b.WriteString(resolved)
		}
	}
	for _, value := range step.Env {
		resolved := interpolate(value, event, outputs)
		if strings.Contains(resolved, automationToken) {
			b.WriteString(resolved)
		}
	}
	return b.Bytes()
}

func interpolateInputs(s string, inputs looseMap, event pullRequestEvent, outputs map[string]map[string]string) string {
	return exprPattern.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(match[3 : len(match)-2])
		if name, ok := strings.CutPrefix(inner, "inputs."); ok {
			return inputs[name]
		}
		value, ok := resolve(inner, event, outputs)
		if !ok {
			return match
		}
		return value
	})
}

func runBash(t *testing.T, dir, script string, env []string) []byte {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "step-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(script); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// actions/runner ScriptHandler invokes bash with the sh argument format "-e {0}"
	// when bash is on PATH. The workflow script itself enables pipefail.
	cmd := exec.CommandContext(ctx, "bash", "-e", file.Name())
	cmd.Dir = dir
	for i, entry := range env {
		if strings.HasPrefix(entry, "GITHUB_WORKSPACE=") {
			env[i] = "GITHUB_WORKSPACE=" + dir
		}
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte(automationToken)) {
		t.Logf("step script exited: %v\n%s", err, out)
	}
	return out
}

func readGitConfig(dir string) []byte {
	data, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		return nil
	}
	return data
}

func globMatch(pattern, name string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '[', ']', '{', '}', '\\':
			b.WriteByte('\\')
			b.WriteByte(pattern[i])
		default:
			b.WriteByte(pattern[i])
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func commitAll(t *testing.T, repo, message string) {
	t.Helper()
	git(t, repo, "git", "add", "-A")
	git(t, repo, "git", "-c", "commit.gpgsign=false", "commit", "-m", message)
}

func revParse(t *testing.T, repo, rev string) string {
	t.Helper()
	return strings.TrimSpace(gitOutput(t, repo, "git", "rev-parse", rev))
}

func git(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	_ = gitOutput(t, dir, name, args...)
}

func gitOutput(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
