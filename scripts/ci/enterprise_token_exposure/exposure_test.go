// Tests for the enterprise clone token handed to pull-request code.
//
// A non-fork pull_request runs .github/workflows from the merge commit and
// checks that commit out. uses: ./ is loaded from that checkout, and the
// following run steps execute files in it (make, local scripts). These tests
// fail while that checkout can observe the grafana-ci-bot token, and pass
// once the token is no longer passed to a workspace action and no longer
// remains in the enterprise clone remote when that action returns.
package enterprise_token_exposure

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const placeholderToken = "PLACEHOLDER_ENTERPRISE_TOKEN"

// prMergeSHA is the pull request merge commit. pull_request workflows and
// $/ actions resolve to this commit, whose tree is the checkout under test.
const prMergeSHA = "1111111111111111111111111111111111111111"

func TestExpressionSemantics(t *testing.T) {
	root := attackContext(false)
	cases := []struct {
		expr string
		want bool
	}{
		{"github.event.pull_request.head.repo.fork == false", true},
		{"github.event.pull_request.head.repo.fork == true", false},
		{"github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false && needs.detect-changes.outputs.changed == 'true'", true},
		{"(github.event_name == 'push' && github.repository == 'grafana/grafana') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork == false)", true},
		{"github.repository == 'grafana/grafana' && needs.detect-changes.outputs.changed == 'true'", true},
		{"needs.detect-changes.outputs.changed == 'true' || needs.detect-changes.outputs.dev-dashboards-changed == 'true'", true},
	}
	for _, tc := range cases {
		got, err := evalBool(tc.expr, root, false)
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %v, want %v", tc.expr, got, tc.want)
		}
	}

	fork := attackContext(true)
	got, err := evalBool("github.event.pull_request.head.repo.fork == false", fork, false)
	if err != nil || got {
		t.Fatalf("fork condition = %v err=%v, want false", got, err)
	}
	// Loose equality: a missing pull_request payload coerces null and false to 0.
	push := map[string]any{
		"github": map[string]any{"event_name": "push", "repository": "grafana/grafana", "event": map[string]any{}},
	}
	got, err = evalBool("github.event.pull_request.head.repo.fork == false", push, false)
	if err != nil || !got {
		t.Fatalf("null == false = %v err=%v, want true", got, err)
	}
}

func TestNonForkPullRequestDoesNotObserveEnterpriseToken(t *testing.T) {
	jobs := discoverJobs(t)
	if len(jobs) == 0 {
		t.Fatal("no pull_request job calls setup-enterprise; the workflows under test were not found")
	}
	t.Logf("checking %d jobs", len(jobs))
	for _, job := range jobs {
		job := job
		t.Run(job.key+"/replaced-action", func(t *testing.T) {
			observeJob(t, job, true, false)
		})
		t.Run(job.key+"/clone-remote", func(t *testing.T) {
			observeJob(t, job, false, false)
		})
	}
}

func TestForkPullRequestDoesNotReceiveEnterpriseToken(t *testing.T) {
	jobs := discoverJobs(t)
	for _, job := range jobs {
		job := job
		t.Run(job.key, func(t *testing.T) {
			observeJob(t, job, true, true)
		})
	}
}

type workflowJob struct {
	key  string
	file string
	id   string
	job  *yaml.Node
	wf   *yaml.Node
}

func discoverJobs(t *testing.T) []workflowJob {
	t.Helper()
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var jobs []workflowJob
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		doc := mustNode(t, path)
		if !triggersPullRequest(mapGet(doc, "on")) {
			continue
		}
		jobMap := mapGet(doc, "jobs")
		if jobMap == nil || jobMap.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(jobMap.Content); i += 2 {
			id := jobMap.Content[i].Value
			body := jobMap.Content[i+1]
			if workflowMentions(body, "setup-enterprise") && workflowMentions(body, "create-github-app-token") {
				jobs = append(jobs, workflowJob{key: name + "/" + id, file: path, id: id, job: body, wf: doc})
			}
		}
	}
	return jobs
}

func observeJob(t *testing.T, job workflowJob, replaceAction, fork bool) {
	t.Helper()
	rootCtx := attackContext(fork)
	if !truthy(evalJobIf(t, job, rootCtx)) {
		return
	}
	canMint := idTokenWrite(job.wf, job.job) && !fork
	repo := repoRoot(t)
	work := t.TempDir()
	ws := filepath.Join(work, "workspace")
	if err := os.MkdirAll(filepath.Join(ws, ".github", "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	trustedAction := filepath.Join(work, "trusted-action")
	copyAction(t, filepath.Join(repo, ".github", "actions", "setup-enterprise"), trustedAction)
	actionDir := filepath.Join(ws, ".github", "actions", "setup-enterprise")
	if replaceAction {
		writeRecorderAction(t, actionDir)
	} else {
		copyAction(t, trustedAction, actionDir)
	}
	writeMakefile(t, filepath.Join(ws, "Makefile"))
	if err := os.WriteFile(filepath.Join(ws, "go.mod"), []byte("module example.com/pr\n\ngo 1.26.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	initGitRepo(t, ws)

	bare := filepath.Join(work, "enterprise.git")
	prepareEnterprise(t, bare)
	capture := filepath.Join(work, "capture")
	gitCfg := filepath.Join(work, "gitconfig")
	writeGitConfig(t, gitCfg, bare)
	home := filepath.Join(work, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(work, "shims")
	writeShims(t, shim)

	env := []string{
		"PATH=" + shim + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home,
		"GITHUB_WORKSPACE=" + ws,
		"TOKEN_CAPTURE_FILE=" + capture,
		"GIT_CONFIG_GLOBAL=" + gitCfg,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GITHUB_HEAD_REF=attacker-branch",
		"GITHUB_BASE_REF=main",
		"SHARD=1/8",
		"CGO_ENABLED=0",
	}

	stepsNode := mapGet(job.job, "steps")
	if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
		t.Fatalf("%s has no steps", job.key)
	}
	failed := false
	for _, stepNode := range stepsNode.Content {
		step := parseStep(stepNode)
		if !stepRuns(t, step, rootCtx, failed) {
			continue
		}
		githubOut := filepath.Join(work, "github-output-"+step.ID)
		githubEnv := filepath.Join(work, "github-env-"+step.ID)
		stepEnv := append([]string{}, env...)
		stepEnv = append(stepEnv, "GITHUB_OUTPUT="+githubOut, "GITHUB_ENV="+githubEnv)
		for k, v := range step.Env {
			stepEnv = append(stepEnv, k+"="+interpolate(t, v, rootCtx))
		}

		switch {
		case isTokenAction(step.Uses):
			if canMint {
				setOutput(rootCtx, step.ID, "token", placeholderToken)
			}
		case isLocalUses(step.Uses):
			dir := resolveLocal(t, step.Uses, ws)
			inputs := interpolateMap(t, step.With, rootCtx)
			runComposite(t, dir, inputs, stepEnv, ws)
		case isSetupEnterprise(step.Uses):
			inputs := interpolateMap(t, step.With, rootCtx)
			runComposite(t, trustedAction, inputs, stepEnv, ws)
		case step.Run != "":
			script := interpolate(t, step.Run, rootCtx)
			materializeRelativeScripts(t, ws, script)
			runBash(t, ws, script, stepEnv)
			if step.ID != "" {
				applyOutputFile(rootCtx, step.ID, githubOut)
			}
		}
		if _, err := os.Stat(githubOut); err == nil && step.ID != "" && !isTokenAction(step.Uses) && step.Run == "" {
			applyOutputFile(rootCtx, step.ID, githubOut)
		}
	}

	got, err := os.ReadFile(capture)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	remote := enterpriseRemote(work)
	if bytes.Contains(got, []byte(placeholderToken)) || strings.Contains(remote, placeholderToken) {
		where := "pull-request code"
		if strings.Contains(remote, placeholderToken) {
			where = "the enterprise clone remote after setup returned"
		}
		if fork {
			t.Fatalf("fork pull request observed the enterprise token via %s", where)
		}
		t.Errorf("non-fork pull request observed the enterprise token via %s", where)
	}
}

func enterpriseRemote(work string) string {
	cfg := filepath.Join(work, "grafana-enterprise", ".git", "config")
	b, err := os.ReadFile(cfg)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "url =") || strings.HasPrefix(line, "url=") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "url ="), "url="))
		}
	}
	return string(b)
}

func runComposite(t *testing.T, dir string, inputs map[string]string, env []string, ws string) {
	t.Helper()
	doc := mustNode(t, filepath.Join(dir, "action.yml"))
	if alt := filepath.Join(dir, "action.yaml"); doc == nil {
		doc = mustNode(t, alt)
	}
	runs := mapGet(doc, "runs")
	steps := mapGet(runs, "steps")
	if steps == nil {
		t.Fatalf("action %s has no runs.steps", dir)
	}
	inputsCtx := map[string]any{}
	for k, v := range inputs {
		inputsCtx[k] = v
	}
	// Composite inputs are a string context visible to embedded steps.
	root := map[string]any{"inputs": inputsCtx}
	for _, stepNode := range steps.Content {
		step := parseStep(stepNode)
		if !stepRuns(t, step, root, false) {
			continue
		}
		if step.Run == "" {
			continue
		}
		stepEnv := append([]string{}, env...)
		merged := map[string]any{"inputs": inputsCtx}
		for k, v := range step.Env {
			stepEnv = append(stepEnv, k+"="+interpolate(t, v, merged))
		}
		script := interpolate(t, step.Run, merged)
		runBash(t, ws, script, stepEnv)
	}
}

func runBash(t *testing.T, dir, script string, env []string) {
	t.Helper()
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Later steps are allowed to fail. Token capture happens before a
		// missing tool or file can stop the recipe that reads the remote.
		t.Logf("step exited: %v\n%s", err, out)
	}
}

func writeRecorderAction(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `name: record
description: pull-request replacement for a local action
inputs:
  token:
    required: false
runs:
  using: composite
  steps:
    - shell: bash
      env:
        GH_TOKEN: ${{ inputs.token }}
      run: |
        f="$TOKEN_CAPTURE_FILE"
        if [ -n "${GH_TOKEN}" ]; then
          printf '%s\n' "$GH_TOKEN" >> "$f"
        fi
        cfg="$GITHUB_WORKSPACE/../grafana-enterprise/.git/config"
        if [ -f "$cfg" ]; then
          cat "$cfg" >> "$f"
        fi
`
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeMakefile(t *testing.T, path string) {
	t.Helper()
	body := `.PHONY: all
%:
	@cat "$(GITHUB_WORKSPACE)/../grafana-enterprise/.git/config" >> "$(TOKEN_CAPTURE_FILE)" 2>/dev/null || true
	@if [ -n "$$GH_TOKEN" ]; then printf '%s\n' "$$GH_TOKEN" >> "$(TOKEN_CAPTURE_FILE)"; fi
	@true
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeShims(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
cfg="${GITHUB_WORKSPACE}/../grafana-enterprise/.git/config"
if [ -f "$cfg" ]; then
  cat "$cfg" >> "$TOKEN_CAPTURE_FILE" 2>/dev/null || true
fi
if [ -n "${GH_TOKEN}" ]; then
  printf '%s\n' "$GH_TOKEN" >> "$TOKEN_CAPTURE_FILE"
fi
exit 0
`
	for _, name := range []string{"go", "yarn", "npm", "node", "mysql", "psql", "sudo", "docker", "python", "python3"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func materializeRelativeScripts(t *testing.T, ws, script string) {
	t.Helper()
	for _, field := range strings.Fields(script) {
		if !strings.HasPrefix(field, "./") {
			continue
		}
		rel := strings.Trim(field, `"'`)
		if strings.ContainsAny(rel, "*?$<>|") {
			continue
		}
		dest := filepath.Join(ws, filepath.Clean(strings.TrimPrefix(rel, "./")))
		if !strings.HasPrefix(dest, ws) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		body := `#!/bin/bash
cfg="${GITHUB_WORKSPACE}/../grafana-enterprise/.git/config"
if [ -f "$cfg" ]; then cat "$cfg" >> "$TOKEN_CAPTURE_FILE"; fi
exit 0
`
		if err := os.WriteFile(dest, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func writeGitConfig(t *testing.T, cfg, bare string) {
	t.Helper()
	if err := os.WriteFile(cfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, filepath.Dir(cfg), "git", "config", "--file", cfg, "protocol.file.allow", "always")
	run(t, filepath.Dir(cfg), "git", "config", "--file", cfg,
		"url."+bare+".insteadOf",
		"https://x-access-token:"+placeholderToken+"@github.com/grafana/grafana-enterprise.git")
}

func prepareEnterprise(t *testing.T, bare string) {
	t.Helper()
	src := t.TempDir()
	run(t, src, "git", "init", "-b", "main")
	run(t, src, "git", "config", "user.email", "test@example.com")
	run(t, src, "git", "config", "user.name", "test")
	build := filepath.Join(src, "build.sh")
	if err := os.WriteFile(build, []byte("#!/bin/bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, src, "git", "add", "build.sh")
	run(t, src, "git", "commit", "-m", "init")
	run(t, src, "git", "clone", "--bare", src, bare)
	run(t, src, "git", "--git-dir", bare, "symbolic-ref", "HEAD", "refs/heads/main")
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run(t, dir, "git", "init", "-b", "main")
	run(t, dir, "git", "config", "user.email", "test@example.com")
	run(t, dir, "git", "config", "user.name", "test")
	run(t, dir, "git", "add", "-A")
	run(t, dir, "git", "commit", "-m", "pr", "--allow-empty")
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(dir, ".gitconfig-empty"),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func copyAction(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(src, "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "action.yml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type parsedStep struct {
	ID, Uses, Run, If string
	With, Env         map[string]string
}

func parseStep(n *yaml.Node) parsedStep {
	s := parsedStep{With: map[string]string{}, Env: map[string]string{}}
	if n == nil || n.Kind != yaml.MappingNode {
		return s
	}
	s.ID = scalar(mapGet(n, "id"))
	s.Uses = scalar(mapGet(n, "uses"))
	s.Run = scalar(mapGet(n, "run"))
	s.If = scalar(mapGet(n, "if"))
	s.With = scalarMap(mapGet(n, "with"))
	s.Env = scalarMap(mapGet(n, "env"))
	return s
}

func stepRuns(t *testing.T, step parsedStep, root map[string]any, failed bool) bool {
	t.Helper()
	cond := strings.TrimSpace(step.If)
	cond = strings.TrimPrefix(cond, "${{")
	cond = strings.TrimSuffix(strings.TrimSpace(cond), "}}")
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return !failed
	}
	ok, err := evalBool(cond, root, failed)
	if err != nil {
		t.Fatalf("if %q: %v", step.If, err)
	}
	return ok
}

func evalJobIf(t *testing.T, job workflowJob, root map[string]any) bool {
	t.Helper()
	cond := scalar(mapGet(job.job, "if"))
	if strings.TrimSpace(cond) == "" {
		return true
	}
	ok, err := evalBool(stripExpr(cond), root, false)
	if err != nil {
		t.Fatalf("%s job if: %v", job.key, err)
	}
	return ok
}

func idTokenWrite(wf, job *yaml.Node) bool {
	perms := mapGet(job, "permissions")
	if perms == nil {
		perms = mapGet(wf, "permissions")
	}
	if perms == nil {
		return false
	}
	if perms.Kind == yaml.ScalarNode {
		return perms.Value == "write-all"
	}
	v := scalar(mapGet(perms, "id-token"))
	return v == "write"
}

func isTokenAction(uses string) bool {
	return strings.Contains(uses, "create-github-app-token@")
}

func isLocalUses(uses string) bool {
	u := strings.TrimSpace(uses)
	return strings.HasPrefix(u, "./") || strings.HasPrefix(u, "$/")
}

func isSetupEnterprise(uses string) bool {
	return strings.Contains(uses, "setup-enterprise") && !isLocalUses(uses)
}

func resolveLocal(t *testing.T, uses, ws string) string {
	t.Helper()
	u := strings.TrimSpace(uses)
	var rel string
	switch {
	case strings.HasPrefix(u, "./"):
		rel = strings.TrimPrefix(u, "./")
	case strings.HasPrefix(u, "$/"):
		// $/ is this repo at the running commit. For pull_request that commit
		// is the merge commit, i.e. the checkout, not an older trusted SHA.
		rel = strings.TrimPrefix(u, "$/")
	default:
		t.Fatalf("not a local action: %s", uses)
	}
	dir := filepath.Join(ws, filepath.FromSlash(rel))
	if strings.Contains(rel, "setup-enterprise") {
		return dir
	}
	if _, err := os.Stat(filepath.Join(dir, "action.yml")); err != nil {
		writeRecorderAction(t, dir)
	}
	return dir
}

func setOutput(root map[string]any, id, name, val string) {
	if id == "" {
		return
	}
	steps, _ := root["steps"].(map[string]any)
	if steps == nil {
		steps = map[string]any{}
		root["steps"] = steps
	}
	cur, _ := steps[id].(map[string]any)
	if cur == nil {
		cur = map[string]any{}
		steps[id] = cur
	}
	outs, _ := cur["outputs"].(map[string]any)
	if outs == nil {
		outs = map[string]any{}
		cur["outputs"] = outs
	}
	outs[name] = val
}

func applyOutputFile(root map[string]any, id, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if ok && key != "" {
			setOutput(root, id, key, val)
		}
	}
}

func interpolateMap(t *testing.T, in map[string]string, root map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for k, v := range in {
		out[k] = interpolate(t, v, root)
	}
	return out
}

func interpolate(t *testing.T, s string, root map[string]any) string {
	t.Helper()
	var b strings.Builder
	for {
		start := strings.Index(s, "${{")
		if start < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		rest := s[start+3:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			t.Fatalf("unclosed expression in %q", s)
		}
		expr := strings.TrimSpace(rest[:end])
		val, err := evalValue(expr, root, false)
		if err != nil {
			t.Fatalf("interpolate %q: %v", expr, err)
		}
		b.WriteString(val.string())
		s = rest[end+2:]
	}
	return b.String()
}

func attackContext(fork bool) map[string]any {
	return map[string]any{
		"github": map[string]any{
			"event_name": "pull_request",
			"repository": "grafana/grafana",
			"workspace":  "",
			"sha":        prMergeSHA,
			"event": map[string]any{
				"pull_request": map[string]any{
					"head": map[string]any{
						"repo": map[string]any{"fork": fork},
						"sha":  prMergeSHA,
					},
				},
			},
		},
		"needs": map[string]any{
			"detect-changes": map[string]any{
				"outputs": map[string]any{
					"changed":                "true",
					"backend":                "true",
					"prettier":               "true",
					"dev-dashboards":         "true",
					"dev-dashboards-changed": "true",
					"run-e2e-tests":          "true",
				},
			},
		},
		"steps": map[string]any{},
		"matrix": map[string]any{
			"shard":  "1/8",
			"total":  "16",
			"name":   "linux/amd64",
			"goos":   "linux",
			"goarch": "amd64",
			"goarm":  "7",
		},
	}
}

func triggersPullRequest(on *yaml.Node) bool {
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == "pull_request"
	case yaml.SequenceNode:
		for _, n := range on.Content {
			if n.Value == "pull_request" {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			if on.Content[i].Value == "pull_request" {
				return true
			}
		}
	}
	return false
}

func workflowMentions(n *yaml.Node, sub string) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.ScalarNode && strings.Contains(n.Value, sub) {
		return true
	}
	for _, c := range n.Content {
		if workflowMentions(c, sub) {
			return true
		}
	}
	return false
}

func mustNode(t *testing.T, path string) *yaml.Node {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		t.Fatalf("%s: empty document", path)
	}
	return doc.Content[0]
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
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

func scalarMap(n *yaml.Node) map[string]string {
	out := map[string]string{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i+1].Kind == yaml.ScalarNode {
			out[n.Content[i].Value] = n.Content[i+1].Value
		}
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "actions", "setup-enterprise", "action.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}

func stripExpr(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "${{")
	s = strings.TrimSuffix(strings.TrimSpace(s), "}}")
	return strings.TrimSpace(s)
}

// Expression subset used by the enterprise workflows.
// Identifiers keep hyphens so needs.detect-changes is one property.
// Loose equality follows GitHub's documented coercion to numbers.

type gval struct {
	kind byte // 0 null, 'b' bool, 'n' number, 's' string
	b    bool
	n    float64
	s    string
}

func (v gval) string() string {
	switch v.kind {
	case 'b':
		if v.b {
			return "true"
		}
		return "false"
	case 'n':
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	case 's':
		return v.s
	default:
		return ""
	}
}

func (v gval) truthy() bool {
	switch v.kind {
	case 'b':
		return v.b
	case 'n':
		return v.n != 0
	case 's':
		return v.s != ""
	default:
		return false
	}
}

func evalBool(expr string, root map[string]any, failed bool) (bool, error) {
	v, err := evalValue(expr, root, failed)
	if err != nil {
		return false, err
	}
	return v.truthy(), nil
}

func truthy(b bool) bool { return b }

type parser struct {
	s      string
	i      int
	root   map[string]any
	failed bool
}

func evalValue(expr string, root map[string]any, failed bool) (gval, error) {
	p := &parser{s: expr, root: root, failed: failed}
	v, err := p.parseOr()
	if err != nil {
		return gval{}, err
	}
	p.skip()
	if p.i != len(p.s) {
		return gval{}, fmt.Errorf("trailing %q", p.s[p.i:])
	}
	return v, nil
}

func (p *parser) parseOr() (gval, error) {
	left, err := p.parseAnd()
	if err != nil {
		return gval{}, err
	}
	for p.has("||") {
		right, err := p.parseAnd()
		if err != nil {
			return gval{}, err
		}
		left = gval{kind: 'b', b: left.truthy() || right.truthy()}
	}
	return left, nil
}

func (p *parser) parseAnd() (gval, error) {
	left, err := p.parseEq()
	if err != nil {
		return gval{}, err
	}
	for p.has("&&") {
		right, err := p.parseEq()
		if err != nil {
			return gval{}, err
		}
		left = gval{kind: 'b', b: left.truthy() && right.truthy()}
	}
	return left, nil
}

func (p *parser) parseEq() (gval, error) {
	left, err := p.parseRel()
	if err != nil {
		return gval{}, err
	}
	for {
		op := ""
		switch {
		case p.has("=="):
			op = "=="
		case p.has("!="):
			op = "!="
		default:
			return left, nil
		}
		right, err := p.parseRel()
		if err != nil {
			return gval{}, err
		}
		eq := looseEqual(left, right)
		if op == "!=" {
			eq = !eq
		}
		left = gval{kind: 'b', b: eq}
	}
}

func (p *parser) parseRel() (gval, error) {
	return p.parseUnary()
}

func (p *parser) parseUnary() (gval, error) {
	p.skip()
	if p.has("!") {
		v, err := p.parseUnary()
		if err != nil {
			return gval{}, err
		}
		return gval{kind: 'b', b: !v.truthy()}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (gval, error) {
	p.skip()
	if p.i >= len(p.s) {
		return gval{}, fmt.Errorf("unexpected end")
	}
	if p.s[p.i] == '(' {
		p.i++
		v, err := p.parseOr()
		if err != nil {
			return gval{}, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return gval{}, fmt.Errorf("missing )")
		}
		p.i++
		return v, nil
	}
	if p.s[p.i] == '\'' || p.s[p.i] == '"' {
		q := p.s[p.i]
		p.i++
		start := p.i
		for p.i < len(p.s) && p.s[p.i] != q {
			p.i++
		}
		if p.i >= len(p.s) {
			return gval{}, fmt.Errorf("unterminated string")
		}
		s := p.s[start:p.i]
		p.i++
		return gval{kind: 's', s: s}, nil
	}
	ident := p.ident()
	if ident == "" {
		return gval{}, fmt.Errorf("expected value at %q", p.s[p.i:])
	}
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return gval{}, fmt.Errorf("only zero-arg functions are supported")
		}
		p.i++
		switch ident {
		case "always":
			return gval{kind: 'b', b: true}, nil
		case "success":
			return gval{kind: 'b', b: !p.failed}, nil
		case "failure":
			return gval{kind: 'b', b: p.failed}, nil
		default:
			return gval{}, fmt.Errorf("unknown function %s", ident)
		}
	}
	switch ident {
	case "true":
		return gval{kind: 'b', b: true}, nil
	case "false":
		return gval{kind: 'b', b: false}, nil
	case "null":
		return gval{}, nil
	}
	path := []string{ident}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '.' {
			break
		}
		p.i++
		next := p.ident()
		if next == "" {
			return gval{}, fmt.Errorf("expected property")
		}
		path = append(path, next)
	}
	return lookup(p.root, path), nil
}

func (p *parser) ident() string {
	p.skip()
	start := p.i
	if p.i < len(p.s) && isIdentStart(p.s[p.i]) {
		p.i++
		for p.i < len(p.s) && isIdentCont(p.s[p.i]) {
			p.i++
		}
	}
	return p.s[start:p.i]
}

func (p *parser) has(op string) bool {
	p.skip()
	if strings.HasPrefix(p.s[p.i:], op) {
		p.i += len(op)
		return true
	}
	return false
}

func (p *parser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\n' || p.s[p.i] == '\t') {
		p.i++
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '-'
}

func lookup(root any, path []string) gval {
	cur := root
	for _, part := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return gval{}
		}
		next, ok := m[part]
		if !ok {
			return gval{}
		}
		cur = next
	}
	switch v := cur.(type) {
	case bool:
		return gval{kind: 'b', b: v}
	case string:
		return gval{kind: 's', s: v}
	case nil:
		return gval{}
	default:
		return gval{}
	}
}

func looseEqual(a, b gval) bool {
	if a.kind == b.kind {
		switch a.kind {
		case 'b':
			return a.b == b.b
		case 'n':
			return a.n == b.n
		case 's':
			return strings.EqualFold(a.s, b.s)
		default:
			return true
		}
	}
	an, aok := asNumber(a)
	bn, bok := asNumber(b)
	if !aok || !bok {
		return false
	}
	if an != an || bn != bn {
		return false
	}
	return an == bn
}

func asNumber(v gval) (float64, bool) {
	switch v.kind {
	case 0:
		return 0, true
	case 'b':
		if v.b {
			return 1, true
		}
		return 0, true
	case 'n':
		return v.n, true
	case 's':
		if v.s == "" {
			return 0, true
		}
		n, err := strconv.ParseFloat(v.s, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
