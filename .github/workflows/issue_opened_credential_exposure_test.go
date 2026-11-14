package issueopened

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests execute the issue-opened workflow's credential hand-off.
// An action ref that is not a full commit SHA is attacker-controlled: the
// runner asks the service to resolve that ref when the job runs, and the
// attacker publishes the action that receives the step inputs. The test
// publishes that action locally and runs it with the environment the runner
// builds for a JavaScript action. The assertions fail while that process can
// see a credential, and pass once every such action is pinned to a full SHA
// or no longer receives one.

const (
	appTokenPlaceholder    = "placeholder-github-app-installation-token"
	oidcTokenPlaceholder   = "placeholder-oidc-request-token"
	oidcURLPlaceholder     = "https://placeholder.example/oidc"
	githubTokenPlaceholder = "placeholder-github-token"
)

func TestIssueOpenedUnpinnedActionsDoNotObserveCredentials(t *testing.T) {
	wf := loadWorkflow(t, workflowSource(t))
	if !triggersIssuesOpened(wf) {
		t.Fatal("workflow parser did not find on.issues.types opened")
	}
	exposures := exposuresFor(t, wf)
	for _, exp := range exposures {
		t.Errorf("credential reached an unpinned action: %s", exp)
	}
}

func TestShaPinnedIssueOpenedWorkflowDoesNotExposeCredentials(t *testing.T) {
	raw := workflowSource(t)
	const sha = "0123456789abcdef0123456789abcdef01234567"
	pinned := strings.ReplaceAll(raw, "@main", "@"+sha)
	pinned = strings.ReplaceAll(pinned, "@get-vault-secrets/v2.0.0", "@"+sha)
	wf := loadWorkflow(t, pinned)
	exposures := exposuresFor(t, wf)
	for _, exp := range exposures {
		t.Errorf("pinned workflow still exposed a credential: %s", exp)
	}
}

func TestJavaScriptActionReceivesWithInputsAsInputEnv(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "seen.json")
	env := map[string]string{
		inputEnvKey("token"):          appTokenPlaceholder,
		inputEnvKey("openai_api_key"): "placeholder-autotriager-openai-api-key",
	}
	seen := runAttackerAction(t, env, sink)
	if seen[inputEnvKey("token")] != appTokenPlaceholder {
		t.Fatalf("INPUT_TOKEN = %q", seen[inputEnvKey("token")])
	}
	if seen[inputEnvKey("openai_api_key")] != "placeholder-autotriager-openai-api-key" {
		t.Fatalf("INPUT_OPENAI_API_KEY = %q", seen[inputEnvKey("openai_api_key")])
	}
}

type scenario struct {
	name          string
	event         string
	repo          string
	actor         string
	association   string
	orgMember     bool
	unlabeledJSON string
}

func exposuresFor(t *testing.T, wf *workflow) []string {
	t.Helper()
	scenarios := []scenario{
		{name: "external issue", event: "issues", repo: "grafana/grafana", actor: "external-user", association: "NONE", unlabeledJSON: "[]"},
		{name: "org member by association", event: "issues", repo: "grafana/grafana", actor: "member-user", association: "MEMBER", unlabeledJSON: "[]"},
		{name: "org member by api", event: "issues", repo: "grafana/grafana", actor: "member-user", association: "NONE", orgMember: true, unlabeledJSON: "[]"},
		{name: "owner association", event: "issues", repo: "grafana/grafana", actor: "owner-user", association: "OWNER", unlabeledJSON: "[]"},
		{name: "contributor issue", event: "issues", repo: "grafana/grafana", actor: "contributor-user", association: "CONTRIBUTOR", unlabeledJSON: "[]"},
		{name: "workflow dispatch backfill", event: "workflow_dispatch", repo: "grafana/grafana", actor: "maintainer", unlabeledJSON: "[1]"},
		{name: "workflow dispatch empty", event: "workflow_dispatch", repo: "grafana/grafana", actor: "maintainer", unlabeledJSON: "[]"},
		{name: "fork issue", event: "issues", repo: "example/grafana", actor: "external-user", association: "NONE", unlabeledJSON: "[]"},
	}
	var out []string
	for _, sc := range scenarios {
		for _, exp := range runScenario(t, wf, sc) {
			out = append(out, sc.name+": "+exp)
		}
	}
	return out
}

type workflow struct {
	triggers issueTrigger
	dispatch bool
	jobs     []*job
}

type issueTrigger struct {
	opened bool
}

type job struct {
	id         string
	ifExpr     string
	needs      []string
	idToken    bool
	outputs    map[string]string
	steps      []*step
	matrixExpr string
	matrixKey  string
}

type step struct {
	id         string
	name       string
	ifExpr     string
	uses       string
	run        string
	with       map[string]string
	env        map[string]string
	continueOn bool
}

func loadWorkflow(t *testing.T, raw string) *workflow {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	wf := &workflow{}
	on := mappingVal(root, "on")
	if on == nil {
		t.Fatal("workflow has no on: key")
	}
	if issues := mappingVal(on, "issues"); issues != nil {
		for _, typ := range seqStrings(mappingVal(issues, "types")) {
			if typ == "opened" {
				wf.triggers.opened = true
			}
		}
	}
	if mappingVal(on, "workflow_dispatch") != nil {
		wf.dispatch = true
	}
	jobs := mappingVal(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		t.Fatal("workflow has no jobs")
	}
	for i := 0; i < len(jobs.Content); i += 2 {
		id := jobs.Content[i].Value
		body := jobs.Content[i+1]
		wf.jobs = append(wf.jobs, parseJob(id, body))
	}
	return wf
}

func parseJob(id string, body *yaml.Node) *job {
	j := &job{id: id, outputs: map[string]string{}}
	if n := mappingVal(body, "if"); n != nil {
		j.ifExpr = scalarString(n)
	}
	if n := mappingVal(body, "needs"); n != nil {
		if n.Kind == yaml.SequenceNode {
			j.needs = seqStrings(n)
		} else {
			j.needs = []string{scalarString(n)}
		}
	}
	if perms := mappingVal(body, "permissions"); perms != nil && perms.Kind == yaml.MappingNode {
		if v := mappingVal(perms, "id-token"); v != nil && scalarString(v) == "write" {
			j.idToken = true
		}
	}
	if outs := mappingVal(body, "outputs"); outs != nil && outs.Kind == yaml.MappingNode {
		for i := 0; i < len(outs.Content); i += 2 {
			j.outputs[outs.Content[i].Value] = scalarString(outs.Content[i+1])
		}
	}
	if strategy := mappingVal(body, "strategy"); strategy != nil {
		if matrix := mappingVal(strategy, "matrix"); matrix != nil && matrix.Kind == yaml.MappingNode && len(matrix.Content) >= 2 {
			j.matrixKey = matrix.Content[0].Value
			j.matrixExpr = scalarString(matrix.Content[1])
		}
	}
	steps := mappingVal(body, "steps")
	if steps != nil {
		for _, st := range steps.Content {
			j.steps = append(j.steps, parseStep(st))
		}
	}
	return j
}

func parseStep(body *yaml.Node) *step {
	st := &step{with: map[string]string{}, env: map[string]string{}}
	if n := mappingVal(body, "id"); n != nil {
		st.id = scalarString(n)
	}
	if n := mappingVal(body, "name"); n != nil {
		st.name = scalarString(n)
	}
	if n := mappingVal(body, "if"); n != nil {
		st.ifExpr = scalarString(n)
	}
	if n := mappingVal(body, "uses"); n != nil {
		st.uses = scalarString(n)
	}
	if n := mappingVal(body, "run"); n != nil {
		st.run = scalarString(n)
	}
	if n := mappingVal(body, "continue-on-error"); n != nil && scalarString(n) == "true" {
		st.continueOn = true
	}
	for _, key := range []string{"with", "env"} {
		block := mappingVal(body, key)
		if block == nil || block.Kind != yaml.MappingNode {
			continue
		}
		dst := st.with
		if key == "env" {
			dst = st.env
		}
		for i := 0; i < len(block.Content); i += 2 {
			dst[block.Content[i].Value] = scalarString(block.Content[i+1])
		}
	}
	return st
}

func triggersIssuesOpened(wf *workflow) bool { return wf.triggers.opened }

func runScenario(t *testing.T, wf *workflow, sc scenario) []string {
	t.Helper()
	if sc.event == "issues" && !wf.triggers.opened {
		return nil
	}
	if sc.event == "workflow_dispatch" && !wf.dispatch {
		return nil
	}
	fakeBin := t.TempDir()
	writeFakeGH(t, fakeBin, sc)
	results := map[string]string{}
	jobOutputs := map[string]map[string]value{}
	var exposures []string
	for _, j := range wf.jobs {
		if !needsMet(j, results) {
			results[j.id] = "skipped"
			continue
		}
		base := baseContext(sc, jobOutputs)
		if j.ifExpr != "" && !isTruthy(mustEval(t, j.ifExpr, base)) {
			results[j.id] = "skipped"
			continue
		}
		matrixValues := []value{nullValue()}
		if j.matrixExpr != "" {
			matrixValues = mustArray(t, mustEval(t, j.matrixExpr, base))
			if len(matrixValues) == 0 {
				results[j.id] = "success"
				continue
			}
		}
		failed := false
		var lastSteps map[string]value
		for _, item := range matrixValues {
			ctx := baseContext(sc, jobOutputs)
			if j.matrixKey != "" {
				ctx.obj["matrix"] = objectValue(map[string]value{j.matrixKey: item})
			}
			stepsCtx := map[string]value{}
			ctx.obj["steps"] = objectValue(stepsCtx)
			for _, st := range j.steps {
				if st.ifExpr != "" && !isTruthy(mustEval(t, st.ifExpr, ctx)) {
					continue
				}
				if st.uses != "" {
					if !actionPinned(st.uses) {
						seen := executeUnpinnedAction(t, j, st, ctx)
						if detail := credentialDetail(seen); detail != "" {
							label := st.name
							if label == "" {
								label = st.id
							}
							exposures = append(exposures, fmt.Sprintf("job %s step %q uses %s: %s", j.id, label, st.uses, detail))
						}
					}
					recordSyntheticOutputs(st, stepsCtx)
				} else if strings.TrimSpace(st.run) != "" && strings.TrimSpace(st.run) != "sleep 2m" {
					code := executeRun(t, fakeBin, st, ctx)
					if code != 0 && !st.continueOn {
						failed = true
						break
					}
				}
				if st.id != "" {
					if _, ok := stepsCtx[st.id]; !ok {
						stepsCtx[st.id] = objectValue(map[string]value{"outputs": objectValue(map[string]value{})})
					}
				}
			}
			lastSteps = stepsCtx
			if failed {
				break
			}
		}
		if failed {
			results[j.id] = "failure"
			continue
		}
		results[j.id] = "success"
		if len(j.outputs) > 0 && lastSteps != nil {
			ctx := baseContext(sc, jobOutputs)
			ctx.obj["steps"] = objectValue(lastSteps)
			outs := map[string]value{}
			for name, expr := range j.outputs {
				outs[name] = mustEval(t, expr, ctx)
			}
			jobOutputs[j.id] = outs
		}
	}
	return exposures
}

func needsMet(j *job, results map[string]string) bool {
	if strings.Contains(j.ifExpr, "always()") {
		return true
	}
	for _, id := range j.needs {
		if results[id] != "success" {
			return false
		}
	}
	return true
}

func recordSyntheticOutputs(st *step, stepsCtx map[string]value) {
	if st.id == "" {
		return
	}
	outs := map[string]value{}
	if cur, ok := stepsCtx[st.id]; ok {
		if existing, ok := cur.obj["outputs"]; ok {
			for k, v := range existing.obj {
				outs[k] = v
			}
		}
	}
	if strings.Contains(st.uses, "create-github-app-token") {
		outs["token"] = stringValue(appTokenPlaceholder)
	}
	if strings.Contains(st.uses, "get-vault-secrets") {
		secrets := map[string]string{}
		for _, line := range strings.Fields(st.with["repo_secrets"]) {
			name, _, ok := strings.Cut(line, "=")
			if ok && name != "" {
				secrets[name] = "placeholder-" + strings.ToLower(strings.ReplaceAll(name, "_", "-"))
			}
		}
		encoded, err := json.Marshal(secrets)
		if err != nil {
			panic(err)
		}
		outs["secrets"] = stringValue(string(encoded))
	}
	if st.id == "auto_triage" {
		outs["triage_labels"] = stringValue("area/example")
	}
	stepsCtx[st.id] = objectValue(map[string]value{"outputs": objectValue(outs)})
}

func executeUnpinnedAction(t *testing.T, j *job, st *step, ctx value) map[string]string {
	t.Helper()
	env := map[string]string{}
	for k, raw := range st.env {
		env[k] = interpolate(t, raw, ctx)
	}
	for k, raw := range st.with {
		env[inputEnvKey(k)] = interpolate(t, raw, ctx)
	}
	if j.idToken {
		// actions/runner v2.338.2 NodeScriptActionHandler sets these on every
		// JavaScript action when the job connection can mint an OIDC token.
		// id-token: write is what makes that connection able to mint one.
		env["ACTIONS_ID_TOKEN_REQUEST_URL"] = oidcURLPlaceholder
		env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = oidcTokenPlaceholder
	}
	sink := filepath.Join(t.TempDir(), "seen.json")
	return runAttackerAction(t, env, sink)
}

func credentialDetail(seen map[string]string) string {
	var parts []string
	for _, key := range sortedKeys(seen) {
		val := seen[key]
		if strings.Contains(val, "placeholder-") || strings.HasPrefix(key, "ACTIONS_ID_TOKEN_") {
			parts = append(parts, key)
		}
	}
	if seen["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] != "" {
		mapping := seen[inputEnvKey("repo_secrets")]
		for _, name := range []string{"AUTOTRIAGER_OPENAI_API_KEY", "AUTOTRIAGER_SLACK_WEBHOOK_URL"} {
			if strings.Contains(mapping, name) {
				parts = append(parts, "vault path mapping names "+name)
			}
		}
	}
	return strings.Join(parts, ", ")
}

func executeRun(t *testing.T, fakeBin string, st *step, ctx value) int {
	t.Helper()
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "step.sh")
	body := interpolate(t, st.run, ctx)
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "github_output")
	if err := os.WriteFile(outputPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Default Linux shell is bash with the sh argument format "-e {0}"
	// (ScriptHandler sets shellCommand to sh, then resolves the bash binary).
	cmd := exec.Command("bash", "-e", scriptPath)
	cmd.Env = []string{
		"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	for k, raw := range st.env {
		cmd.Env = append(cmd.Env, k+"="+interpolate(t, raw, ctx))
	}
	cmd.Env = append(cmd.Env, "GITHUB_OUTPUT="+outputPath)
	cmd.Dir = dir
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errorsAs(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run step %q: %v", st.name, err)
		}
	}
	if st.id != "" {
		parsed := parseGitHubOutput(t, outputPath)
		outs := map[string]value{}
		for k, v := range parsed {
			outs[k] = stringValue(v)
		}
		steps := ctx.obj["steps"]
		steps.obj[st.id] = objectValue(map[string]value{"outputs": objectValue(outs)})
	}
	return code
}

func runAttackerAction(t *testing.T, env map[string]string, sink string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "index.js")
	const payload = `
const fs = require('fs');
const seen = {};
for (const [key, value] of Object.entries(process.env)) {
  if (key.startsWith('INPUT_') || key.startsWith('ACTIONS_ID_TOKEN_')) {
    seen[key] = value;
  }
}
fs.writeFileSync(process.argv[1], JSON.stringify(seen));
`
	// argv[1] is the sink. The runner invokes node with the action entrypoint
	// as the script path; this payload is that entrypoint and records the
	// environment the runner passed to the process.
	js := strings.Replace(payload, "process.argv[1]", strconv.Quote(sink), 1)
	if err := os.WriteFile(script, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attacker action: %v\n%s", err, out)
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	if err := json.Unmarshal(data, &seen); err != nil {
		t.Fatal(err)
	}
	return seen
}

func writeFakeGH(t *testing.T, dir string, sc scenario) {
	t.Helper()
	member := "exit 1"
	if sc.orgMember {
		member = "exit 0"
	}
	body := fmt.Sprintf(`#!/bin/bash
if [[ "$1" == "api" ]]; then
  %s
fi
if [[ "$1" == "issue" && "$2" == "list" ]]; then
  printf '%%s\n' '%s'
  exit 0
fi
if [[ "$1" == "issue" ]]; then
  exit 0
fi
echo "unexpected gh command" >&2
exit 2
`, member, sc.unlabeledJSON)
	path := filepath.Join(dir, "gh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func inputEnvKey(name string) string {
	return "INPUT_" + strings.ToUpper(strings.ReplaceAll(name, " ", "_"))
}

func actionPinned(uses string) bool {
	uses = strings.TrimSpace(uses)
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "$/") {
		return true
	}
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return false
	}
	ref := uses[at+1:]
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

func workflowSource(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "issue-opened.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mappingVal(n *yaml.Node, key string) *yaml.Node {
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

func seqStrings(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range n.Content {
		out = append(out, scalarString(item))
	}
	return out
}

func scalarString(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small maps; insertion order is not stable and the assertion only joins them.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func errorsAs(err error, target **exec.ExitError) bool {
	if err == nil {
		return false
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	*target = ee
	return true
}

// Expression evaluation follows actions/runner v2.338.2
// EvaluationResult.AbstractEqual / IsFalsy: string equality is case-insensitive,
// and null coerces to 0 so a missing output compared with "true" is not equal.

type kind int

const (
	kindNull kind = iota
	kindString
	kindBool
	kindNumber
	kindObject
	kindArray
)

type value struct {
	kind kind
	s    string
	b    bool
	n    float64
	obj  map[string]value
	arr  []value
}

func nullValue() value { return value{kind: kindNull} }
func stringValue(s string) value {
	return value{kind: kindString, s: s}
}
func boolValue(b bool) value { return value{kind: kindBool, b: b} }
func numberValue(n float64) value {
	return value{kind: kindNumber, n: n}
}
func objectValue(obj map[string]value) value {
	return value{kind: kindObject, obj: obj}
}

func baseContext(sc scenario, jobOutputs map[string]map[string]value) value {
	issue := map[string]value{
		"number":             numberValue(123),
		"author_association": stringValue(sc.association),
		"html_url":           stringValue("https://example.test/grafana/grafana/issues/123"),
	}
	event := map[string]value{}
	if sc.event == "issues" {
		event["issue"] = objectValue(issue)
		event["action"] = stringValue("opened")
	}
	repoName := sc.repo
	if i := strings.LastIndex(repoName, "/"); i >= 0 {
		repoName = repoName[i+1:]
	}
	github := map[string]value{
		"repository":       stringValue(sc.repo),
		"repository_owner": stringValue(strings.Split(sc.repo, "/")[0]),
		"event_name":       stringValue(sc.event),
		"actor":            stringValue(sc.actor),
		"workspace":        stringValue("/tmp/github-workspace"),
		"event":            objectValue(event),
	}
	needs := map[string]value{}
	for id, outs := range jobOutputs {
		needs[id] = objectValue(map[string]value{"outputs": objectValue(outs)})
	}
	env := map[string]value{"ACTOR": stringValue(sc.actor)}
	return objectValue(map[string]value{
		"github":                  objectValue(github),
		"needs":                   objectValue(needs),
		"env":                     objectValue(env),
		"inputs":                  objectValue(map[string]value{"limit": stringValue("10")}),
		"secrets":                 objectValue(map[string]value{"GITHUB_TOKEN": stringValue(githubTokenPlaceholder)}),
		"github_event_repository": objectValue(map[string]value{"name": stringValue(repoName)}),
	})
}

func mustEval(t *testing.T, expr string, ctx value) value {
	t.Helper()
	v, err := evalExpr(strings.TrimSpace(stripExpr(expr)), ctx)
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	return v
}

func mustArray(t *testing.T, v value) []value {
	t.Helper()
	if v.kind != kindArray {
		t.Fatalf("matrix value is %s, want array", kindName(v.kind))
	}
	return v.arr
}

func stripExpr(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		return strings.TrimSpace(s[3 : len(s)-2])
	}
	return s
}

func interpolate(t *testing.T, raw string, ctx value) string {
	t.Helper()
	var b strings.Builder
	rest := raw
	for {
		start := strings.Index(rest, "${{")
		if start < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:start])
		rest = rest[start+3:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			t.Fatalf("unclosed expression in %q", raw)
		}
		v, err := evalExpr(strings.TrimSpace(rest[:end]), ctx)
		if err != nil {
			t.Fatalf("eval %q: %v", rest[:end], err)
		}
		b.WriteString(render(v))
		rest = rest[end+2:]
	}
	return b.String()
}

func isTruthy(v value) bool {
	switch v.kind {
	case kindNull:
		return false
	case kindBool:
		return v.b
	case kindNumber:
		return v.n != 0 && !math.IsNaN(v.n)
	case kindString:
		return v.s != ""
	default:
		return true
	}
}

func render(v value) string {
	switch v.kind {
	case kindNull:
		return ""
	case kindString:
		return v.s
	case kindBool:
		if v.b {
			return "true"
		}
		return "false"
	case kindNumber:
		if v.n == math.Trunc(v.n) && !math.IsNaN(v.n) && !math.IsInf(v.n, 0) {
			return strconv.FormatInt(int64(v.n), 10)
		}
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	default:
		encoded, _ := json.Marshal(encodeJSON(v))
		return string(encoded)
	}
}

func encodeJSON(v value) any {
	switch v.kind {
	case kindNull:
		return nil
	case kindString:
		return v.s
	case kindBool:
		return v.b
	case kindNumber:
		return v.n
	case kindArray:
		arr := make([]any, len(v.arr))
		for i, item := range v.arr {
			arr[i] = encodeJSON(item)
		}
		return arr
	case kindObject:
		obj := map[string]any{}
		for k, item := range v.obj {
			obj[k] = encodeJSON(item)
		}
		return obj
	default:
		return nil
	}
}

type parser struct {
	s   string
	i   int
	ctx value
}

func evalExpr(expr string, ctx value) (value, error) {
	p := &parser{s: expr, ctx: ctx}
	v, err := p.parseOr()
	if err != nil {
		return value{}, err
	}
	p.skip()
	if p.i != len(p.s) {
		return value{}, fmt.Errorf("trailing %q", p.s[p.i:])
	}
	return v, nil
}

func (p *parser) parseOr() (value, error) {
	left, err := p.parseAnd()
	if err != nil {
		return value{}, err
	}
	for {
		p.skip()
		if !p.consume("||") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return value{}, err
		}
		left = boolValue(isTruthy(left) || isTruthy(right))
	}
}

func (p *parser) parseAnd() (value, error) {
	left, err := p.parseEq()
	if err != nil {
		return value{}, err
	}
	for {
		p.skip()
		if !p.consume("&&") {
			return left, nil
		}
		right, err := p.parseEq()
		if err != nil {
			return value{}, err
		}
		left = boolValue(isTruthy(left) && isTruthy(right))
	}
}

func (p *parser) parseEq() (value, error) {
	left, err := p.parseUnary()
	if err != nil {
		return value{}, err
	}
	for {
		p.skip()
		op := ""
		switch {
		case p.consume("!="):
			op = "!="
		case p.consume("=="):
			op = "=="
		default:
			return left, nil
		}
		right, err := p.parseUnary()
		if err != nil {
			return value{}, err
		}
		eq := abstractEqual(left, right)
		if op == "!=" {
			eq = !eq
		}
		left = boolValue(eq)
	}
}

func (p *parser) parseUnary() (value, error) {
	p.skip()
	if p.consume("!") {
		v, err := p.parseUnary()
		if err != nil {
			return value{}, err
		}
		return boolValue(!isTruthy(v)), nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (value, error) {
	p.skip()
	if p.consume("(") {
		v, err := p.parseOr()
		if err != nil {
			return value{}, err
		}
		p.skip()
		if !p.consume(")") {
			return value{}, fmt.Errorf("missing )")
		}
		return v, nil
	}
	if p.peek() == '\'' || p.peek() == '"' {
		return p.parseString()
	}
	if isDigit(p.peek()) {
		return p.parseNumber()
	}
	name, ok := p.parseIdent()
	if !ok {
		return value{}, fmt.Errorf("expected value at %q", p.s[p.i:])
	}
	var v value
	p.skip()
	if p.consume("(") {
		var args []value
		p.skip()
		if !p.consume(")") {
			for {
				arg, err := p.parseOr()
				if err != nil {
					return value{}, err
				}
				args = append(args, arg)
				p.skip()
				if p.consume(")") {
					break
				}
				if !p.consume(",") {
					return value{}, fmt.Errorf("expected , or )")
				}
			}
		}
		var err error
		v, err = callFunction(name, args)
		if err != nil {
			return value{}, err
		}
	} else {
		var err error
		v, err = indexValue(p.ctx, name)
		if err != nil {
			return value{}, err
		}
	}
	for {
		p.skip()
		if p.consume(".") {
			prop, ok := p.parseIdent()
			if !ok {
				return value{}, fmt.Errorf("expected property")
			}
			var err error
			v, err = indexValue(v, prop)
			if err != nil {
				return value{}, err
			}
			continue
		}
		if p.consume("[") {
			key, err := p.parsePrimary()
			if err != nil {
				return value{}, err
			}
			p.skip()
			if !p.consume("]") {
				return value{}, fmt.Errorf("expected ]")
			}
			var ierr error
			v, ierr = indexValue(v, render(key))
			if ierr != nil {
				return value{}, ierr
			}
			continue
		}
		return v, nil
	}
}

func callFunction(name string, args []value) (value, error) {
	switch name {
	case "fromJSON":
		if len(args) != 1 {
			return value{}, fmt.Errorf("fromJSON expects 1 arg")
		}
		if args[0].kind != kindString {
			return nullValue(), nil
		}
		var decoded any
		if err := json.Unmarshal([]byte(args[0].s), &decoded); err != nil {
			return value{}, err
		}
		return fromAny(decoded), nil
	case "always", "success":
		return boolValue(true), nil
	case "failure":
		return boolValue(false), nil
	default:
		return value{}, fmt.Errorf("unsupported function %s", name)
	}
}

func fromAny(v any) value {
	switch n := v.(type) {
	case nil:
		return nullValue()
	case string:
		return stringValue(n)
	case bool:
		return boolValue(n)
	case float64:
		return numberValue(n)
	case []any:
		arr := make([]value, len(n))
		for i, item := range n {
			arr[i] = fromAny(item)
		}
		return value{kind: kindArray, arr: arr}
	case map[string]any:
		obj := map[string]value{}
		for k, item := range n {
			obj[k] = fromAny(item)
		}
		return objectValue(obj)
	default:
		return stringValue(fmt.Sprint(v))
	}
}

func indexValue(v value, key string) (value, error) {
	if v.kind != kindObject {
		return nullValue(), nil
	}
	child, ok := v.obj[key]
	if !ok {
		return nullValue(), nil
	}
	return child, nil
}

func (p *parser) parseString() (value, error) {
	quote := p.peek()
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		ch := p.s[p.i]
		p.i++
		if ch == quote {
			return stringValue(b.String()), nil
		}
		if ch == '\\' && p.i < len(p.s) {
			b.WriteByte(p.s[p.i])
			p.i++
			continue
		}
		b.WriteByte(ch)
	}
	return value{}, fmt.Errorf("unterminated string")
}

func (p *parser) parseNumber() (value, error) {
	start := p.i
	for p.i < len(p.s) && (isDigit(p.s[p.i]) || p.s[p.i] == '.') {
		p.i++
	}
	n, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil {
		return value{}, err
	}
	return numberValue(n), nil
}

func (p *parser) parseIdent() (string, bool) {
	p.skip()
	start := p.i
	if p.i >= len(p.s) || !isIdentStart(p.s[p.i]) {
		return "", false
	}
	p.i++
	for p.i < len(p.s) && isIdentCont(p.s[p.i]) {
		p.i++
	}
	return p.s[start:p.i], true
}

func (p *parser) consume(lit string) bool {
	p.skip()
	if strings.HasPrefix(p.s[p.i:], lit) {
		p.i += len(lit)
		return true
	}
	return false
}

func (p *parser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n') {
		p.i++
	}
}

func (p *parser) peek() byte {
	p.skip()
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
func isIdentCont(b byte) bool {
	return isIdentStart(b) || isDigit(b) || b == '-'
}

func abstractEqual(left, right value) bool {
	left, right = coerce(left, right)
	if left.kind != right.kind {
		return false
	}
	switch left.kind {
	case kindNull:
		return true
	case kindString:
		return strings.EqualFold(left.s, right.s)
	case kindBool:
		return left.b == right.b
	case kindNumber:
		if math.IsNaN(left.n) || math.IsNaN(right.n) {
			return false
		}
		return left.n == right.n
	default:
		return false
	}
}

func coerce(left, right value) (value, value) {
	if left.kind == right.kind {
		return left, right
	}
	if left.kind == kindNumber && right.kind == kindString {
		return left, numberValue(parseNumber(right.s))
	}
	if left.kind == kindString && right.kind == kindNumber {
		return numberValue(parseNumber(left.s)), right
	}
	if left.kind == kindBool || left.kind == kindNull {
		return coerce(numberValue(toNumber(left)), right)
	}
	if right.kind == kindBool || right.kind == kindNull {
		return coerce(left, numberValue(toNumber(right)))
	}
	return left, right
}

func toNumber(v value) float64 {
	switch v.kind {
	case kindNull:
		return 0
	case kindBool:
		if v.b {
			return 1
		}
		return 0
	case kindNumber:
		return v.n
	case kindString:
		return parseNumber(v.s)
	default:
		return math.NaN()
	}
}

func parseNumber(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return n
}

func kindName(k kind) string {
	switch k {
	case kindNull:
		return "null"
	case kindString:
		return "string"
	case kindBool:
		return "bool"
	case kindNumber:
		return "number"
	case kindObject:
		return "object"
	case kindArray:
		return "array"
	default:
		return "unknown"
	}
}
