package workflowtoken

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// placeholderToken is an obvious stand-in for the installation token the
// create-github-app-token action writes to its token output. It is not a
// credential.
const placeholderToken = "PLACEHOLDER_ENTERPRISE_CLONE_TOKEN"

// attackerRef is the uses ref that means "the pull request head", so a pin to
// this ref still loads the pull request copy of an action.
const attackerRef = "attacker-pr-head"

func TestNonForkPullRequestCodeCannotReadEnterpriseCloneToken(t *testing.T) {
	root := repoRoot(t)
	gitSrv := startEnterpriseGitServer(t)

	events := []event{
		{
			name:       "pull_request from a branch in this repository",
			eventName:  "pull_request",
			fork:       boolPtr(false),
			repository: "grafana/grafana",
		},
		{
			name:       "workflow_dispatch, where the fork property is absent",
			eventName:  "workflow_dispatch",
			fork:       nil,
			repository: "grafana/grafana",
		},
	}

	var exercised int
	for _, ev := range events {
		ev := ev
		t.Run(ev.name, func(t *testing.T) {
			jobs := enterpriseTokenJobs(t, root, ev)
			if ev.eventName == "pull_request" && len(jobs) == 0 {
				t.Fatal("parser found no job that passes the enterprise token on a non-fork pull request")
			}
			for _, job := range jobs {
				job := job
				for _, preserve := range []bool{false, true} {
					preserve := preserve
					label := "replaced setup-enterprise action"
					if preserve {
						label = "real setup-enterprise action, later pull request commands"
					}
					t.Run(job.name+"/"+label, func(t *testing.T) {
						exercised++
						sink := runJob(t, root, gitSrv, job, ev, preserve)
						if bytes.Contains(sink, []byte(placeholderToken)) {
							t.Errorf("pull request code read the enterprise clone token in %s job %s (%s)", filepath.Base(job.workflow), job.name, label)
						}
					})
				}
			}
		})
	}
	if exercised == 0 {
		t.Fatal("no enterprise token job was exercised")
	}
}

func TestForkPullRequestDoesNotReceiveEnterpriseCloneToken(t *testing.T) {
	root := repoRoot(t)
	gitSrv := startEnterpriseGitServer(t)
	ev := event{
		name:       "pull_request from a fork",
		eventName:  "pull_request",
		fork:       boolPtr(true),
		repository: "grafana/grafana",
	}
	for _, job := range enterpriseTokenJobs(t, root, ev) {
		sink := runJob(t, root, gitSrv, job, ev, false)
		if bytes.Contains(sink, []byte(placeholderToken)) {
			t.Errorf("fork pull request code read the enterprise clone token in %s job %s", filepath.Base(job.workflow), job.name)
		}
	}
}

type event struct {
	name       string
	eventName  string
	fork       *bool
	repository string
}

func boolPtr(v bool) *bool { return &v }

type jobRun struct {
	workflow string
	name     string
	steps    []map[string]any
}

func enterpriseTokenJobs(t *testing.T, root string, ev event) []jobRun {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := ev.context()
	var jobs []jobRun
	for _, path := range matches {
		wf := readYAML(t, path)
		if !triggersPullRequestOrDispatch(wf, ev.eventName) {
			continue
		}
		rawJobs, _ := wf["jobs"].(map[string]any)
		for name, raw := range rawJobs {
			job, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			steps, ok := job["steps"].([]any)
			if !ok {
				continue
			}
			parsed := make([]map[string]any, 0, len(steps))
			passesToken := false
			for _, rawStep := range steps {
				step, ok := rawStep.(map[string]any)
				if !ok {
					continue
				}
				parsed = append(parsed, step)
				if stepPassesEnterpriseToken(step) {
					passesToken = true
				}
			}
			if !passesToken {
				continue
			}
			jobIf, err := evalIfResult(job["if"], ctx)
			if err != nil {
				t.Fatalf("%s job %s: cannot evaluate condition %v: %v", path, name, job["if"], err)
			}
			if !truthy(jobIf) {
				continue
			}
			jobs = append(jobs, jobRun{workflow: path, name: name, steps: parsed})
		}
	}
	return jobs
}

func triggersPullRequestOrDispatch(wf map[string]any, eventName string) bool {
	on, ok := wf["on"]
	if !ok {
		on = wf["true"] // yaml.v3 may decode the key "on" only as on; kept for safety
	}
	switch v := on.(type) {
	case string:
		return v == eventName
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == eventName {
				return true
			}
		}
	case map[string]any:
		_, ok := v[eventName]
		return ok
	}
	return false
}

func stepPassesEnterpriseToken(step map[string]any) bool {
	uses, _ := step["uses"].(string)
	if !strings.Contains(uses, "setup-enterprise") {
		return false
	}
	with, _ := step["with"].(map[string]any)
	token, _ := with["token"].(string)
	return strings.Contains(token, "outputs.token")
}

func (ev event) context() map[string]val {
	fork := val{kind: kindNull}
	if ev.fork != nil {
		fork = val{kind: kindBool, b: *ev.fork}
	}
	ctx := map[string]val{
		"github.event_name":                        {kind: kindString, s: ev.eventName},
		"github.repository":                        {kind: kindString, s: ev.repository},
		"github.event.pull_request.head.repo.fork": fork,
	}
	// Change-detection reports a modification as the string true. The attacker
	// changes a backend file, which the backend pattern list includes.
	for _, key := range []string{
		"needs.detect-changes.outputs.changed",
		"needs.detect-changes.outputs.backend",
		"needs.detect-changes.outputs.prettier",
		"needs.detect-changes.outputs.changed-frontend-packages",
		"needs.detect-changes.outputs.changed-frontend-dependencies",
	} {
		ctx[key] = val{kind: kindString, s: "true"}
	}
	return ctx
}

func runJob(t *testing.T, root string, gitSrv *gitServer, job jobRun, ev event, preserveEnterpriseAction bool) []byte {
	t.Helper()
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".github", "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	sinkPath := filepath.Join(dir, "sink")
	overlayPullRequestTree(t, root, workspace, preserveEnterpriseAction)

	ctx := ev.context()
	stepOutputs := map[string]map[string]string{}
	priorFailed := false
	for _, step := range job.steps {
		if priorFailed {
			// The runner's default step condition is success().
			continue
		}
		if !truthy(evalIf(t, step["if"], withStepOutputs(ctx, stepOutputs))) {
			continue
		}
		id, _ := step["id"].(string)
		uses, _ := step["uses"].(string)
		switch {
		case uses == "":
			script := expandExpressions(t, fmt.Sprint(step["run"]), withStepOutputs(ctx, stepOutputs))
			// make executes the pull request Makefile. Other run scripts reach
			// pull request programs (go test, yarn, relative scripts) which can
			// read the enterprise remote the same way.
			if strings.Contains(script, "make") {
				runScript(t, workspace, sinkPath, gitSrv, script, nil)
			} else if strings.TrimSpace(script) != "" && script != "<nil>" {
				recordEnterpriseRemote(t, workspace, sinkPath, gitSrv)
			}
		case strings.Contains(uses, "create-github-app-token"):
			if id == "" {
				t.Fatalf("%s job %s mints a token without a step id", job.workflow, job.name)
			}
			stepOutputs[id] = map[string]string{"token": placeholderToken}
		case isLocalOrPinnedAction(uses):
			actionDir := resolveAction(uses, workspace, root)
			manifest := readYAML(t, filepath.Join(actionDir, "action.yml"))
			if failed := runComposite(t, workspace, sinkPath, gitSrv, manifest, stepInputs(step, stepOutputs)); failed {
				priorFailed = true
			}
		default:
			// actions/checkout and other remote actions are not the pull request tree.
		}
	}
	sink, err := os.ReadFile(sinkPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return sink
}

func withStepOutputs(ctx map[string]val, outputs map[string]map[string]string) map[string]val {
	out := make(map[string]val, len(ctx)+8)
	for k, v := range ctx {
		out[k] = v
	}
	for id, pairs := range outputs {
		for name, value := range pairs {
			out["steps."+id+".outputs."+name] = val{kind: kindString, s: value}
		}
	}
	return out
}

func stepInputs(step map[string]any, outputs map[string]map[string]string) map[string]string {
	with, _ := step["with"].(map[string]any)
	inputs := map[string]string{}
	ctx := withStepOutputs(map[string]val{}, outputs)
	for k, raw := range with {
		inputs[k] = stringify(evalIf(nil, raw, ctx))
	}
	return inputs
}

func overlayPullRequestTree(t *testing.T, root, workspace string, preserveEnterpriseAction bool) {
	t.Helper()
	// The merge commit keeps the workflow from the base and replaces the files
	// the attacker committed: the local actions the jobs execute and the Makefile
	// those jobs invoke. preserveEnterpriseAction keeps the base setup-enterprise
	// action, which is the case where only the following commands were replaced.
	mustWrite(t, filepath.Join(workspace, "Makefile"), maliciousMakefile)
	entries, err := os.ReadDir(filepath.Join(root, ".github", "actions"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		src := filepath.Join(root, ".github", "actions", entry.Name(), "action.yml")
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dstDir := filepath.Join(workspace, ".github", "actions", entry.Name())
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := maliciousAction
		if preserveEnterpriseAction && entry.Name() == "setup-enterprise" {
			original, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			body = string(original)
		}
		mustWrite(t, filepath.Join(dstDir, "action.yml"), body)
	}
}

func expandExpressions(t *testing.T, script string, ctx map[string]val) string {
	var b strings.Builder
	for {
		start := strings.Index(script, "${{")
		if start < 0 {
			b.WriteString(script)
			break
		}
		b.WriteString(script[:start])
		rest := script[start+3:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			b.WriteString(script[start:])
			break
		}
		b.WriteString(stringify(evalIf(t, strings.TrimSpace(rest[:end]), ctx)))
		script = rest[end+2:]
	}
	return b.String()
}

func recordEnterpriseRemote(t *testing.T, workspace, sinkPath string, gitSrv *gitServer) {
	t.Helper()
	runScript(t, workspace, sinkPath, gitSrv, "url=$(git -C \"$GITHUB_WORKSPACE/../grafana-enterprise\" config --get remote.origin.url 2>/dev/null || true); if [ -n \"$url\" ]; then printf '%s\\n' \"$url\" >> \"$EXFIL_SINK\"; fi", nil)
}

const maliciousAction = `name: Pull request action
description: Replacement from the pull request tree
inputs:
  token:
    description: token input
    required: false
    default: ''
  go-version-file:
    required: false
    default: ''
  cache:
    required: false
    default: ''
  cache-build:
    required: false
    default: ''
runs:
  using: composite
  steps:
    - shell: bash
      env:
        GH_TOKEN: ${{ inputs.token }}
      run: |
        if [ -n "${GH_TOKEN}" ]; then printf '%s\n' "$GH_TOKEN" >> "$EXFIL_SINK"; fi
        url=$(git -C "$GITHUB_WORKSPACE/../grafana-enterprise" config --get remote.origin.url 2>/dev/null || true)
        if [ -n "$url" ]; then printf '%s\n' "$url" >> "$EXFIL_SINK"; fi
`

const maliciousMakefile = `%:
	@url=$$(git -C "$$GITHUB_WORKSPACE/../grafana-enterprise" config --get remote.origin.url 2>/dev/null || true); if [ -n "$$url" ]; then printf '%s\n' "$$url" >> "$$EXFIL_SINK"; fi
`

func isLocalOrPinnedAction(uses string) bool {
	return strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, `.\\`) || strings.Contains(uses, "setup-enterprise")
}

func resolveAction(uses, workspace, base string) string {
	uses = strings.TrimSpace(uses)
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, `.\\`) {
		rel := strings.TrimPrefix(uses, "./")
		rel = strings.TrimPrefix(rel, `.\\`)
		return filepath.Join(workspace, filepath.FromSlash(rel))
	}
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return filepath.Join(workspace, uses)
	}
	ref := uses[at+1:]
	segs := strings.Split(uses[:at], "/")
	rel := ""
	if len(segs) > 2 {
		rel = strings.Join(segs[2:], "/")
	}
	// A pin to the pull request head is still the pull request tree. Any other
	// ref is the base commit's copy of that action.
	if ref == attackerRef {
		return filepath.Join(workspace, filepath.FromSlash(rel))
	}
	return filepath.Join(base, filepath.FromSlash(rel))
}

func runComposite(t *testing.T, workspace, sinkPath string, gitSrv *gitServer, manifest map[string]any, inputs map[string]string) bool {
	t.Helper()
	runs, _ := manifest["runs"].(map[string]any)
	steps, _ := runs["steps"].([]any)
	inputCtx := map[string]val{}
	for k, v := range inputs {
		inputCtx["inputs."+k] = val{kind: kindString, s: v}
	}
	failed := false
	for _, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if !truthy(evalIf(t, step["if"], inputCtx)) {
			continue
		}
		env := map[string]string{}
		if rawEnv, ok := step["env"].(map[string]any); ok {
			for k, rawV := range rawEnv {
				env[fmt.Sprint(k)] = stringify(evalIf(t, rawV, inputCtx))
			}
		}
		script := fmt.Sprint(step["run"])
		if script == "" || script == "<nil>" {
			continue
		}
		if runScript(t, workspace, sinkPath, gitSrv, script, env) != 0 {
			failed = true
			break
		}
	}
	return failed
}

func runScript(t *testing.T, workspace, sinkPath string, gitSrv *gitServer, script string, extra map[string]string) int {
	t.Helper()
	if strings.TrimSpace(script) == "" || script == "<nil>" {
		return 0
	}
	file := filepath.Join(t.TempDir(), "step.sh")
	mustWrite(t, file, script)
	cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", file)
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(),
		"GITHUB_WORKSPACE="+workspace,
		"EXFIL_SINK="+sinkPath,
		"GITHUB_HEAD_REF=main",
		"GITHUB_BASE_REF=main",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0="+gitSrv.insteadOfKey,
		"GIT_CONFIG_VALUE_0="+gitSrv.insteadOfValue,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("run step: %v\n%s", err, out)
		}
		var exitErr *exec.ExitError
		if ok := errorAs(err, &exitErr); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

func errorAs(err error, target **exec.ExitError) bool {
	exitErr, ok := err.(*exec.ExitError)
	if ok {
		*target = exitErr
	}
	return ok
}

type gitServer struct {
	url            string
	insteadOfKey   string
	insteadOfValue string
}

func startEnterpriseGitServer(t *testing.T) *gitServer {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "grafana-enterprise.git")
	src := filepath.Join(root, "src")
	git(t, "", "init", "--bare", bare)
	git(t, "", "init", "-b", "main", src)
	mustWrite(t, filepath.Join(src, "build.sh"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(src, "build.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "build.sh")
	git(t, src, "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-m", "init")
	git(t, "", "--git-dir="+bare, "fetch", src, "HEAD:refs/heads/main")
	git(t, "", "--git-dir="+bare, "symbolic-ref", "HEAD", "refs/heads/main")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: gitHTTPBackend(bare)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	base := "http://" + ln.Addr().String() + "/grafana-enterprise.git"
	tokenURL := "https://x-access-token:" + placeholderToken + "@github.com/grafana/grafana-enterprise.git"
	return &gitServer{
		url:            base,
		insteadOfKey:   "url." + base + ".insteadOf",
		insteadOfValue: tokenURL,
	}
}

func gitHTTPBackend(projectRoot string) http.Handler {
	parent := filepath.Dir(projectRoot)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.ContentLength > 0 {
			buf := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(buf)
			body = buf
		}
		cmd := exec.Command("git", "http-backend")
		cmd.Stdin = bytes.NewReader(body)
		cmd.Env = append(os.Environ(),
			"GIT_PROJECT_ROOT="+parent,
			"GIT_HTTP_EXPORT_ALL=1",
			"REQUEST_METHOD="+r.Method,
			"PATH_INFO="+r.URL.Path,
			"QUERY_STRING="+r.URL.RawQuery,
			"CONTENT_TYPE="+r.Header.Get("Content-Type"),
			"CONTENT_LENGTH="+strconv.FormatInt(int64(len(body)), 10),
		)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, "git http-backend", http.StatusBadGateway)
			return
		}
		head, resp, _ := bytes.Cut(out, []byte("\r\n\r\n"))
		status := http.StatusOK
		for _, line := range bytes.Split(head, []byte("\r\n")) {
			if len(line) == 0 {
				continue
			}
			k, v, ok := bytes.Cut(line, []byte(":"))
			if !ok {
				continue
			}
			if bytes.EqualFold(k, []byte("Status")) {
				fields := bytes.Fields(v)
				if len(fields) > 0 {
					if n, err := strconv.Atoi(string(fields[0])); err == nil {
						status = n
					}
				}
				continue
			}
			w.Header().Add(string(k), strings.TrimSpace(string(v)))
		}
		w.WriteHeader(status)
		_, _ = w.Write(resp)
	})
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// Expression evaluation follows the runner's AbstractEqual coercion and
// operator precedence (&& binds tighter than ||). Enough of the language is
// implemented to evaluate the conditions these workflows actually use.

const (
	kindNull = iota
	kindBool
	kindString
	kindNumber
)

type val struct {
	kind int
	b    bool
	s    string
	n    float64
}

func evalIf(t *testing.T, raw any, ctx map[string]val) val {
	v, err := evalIfResult(raw, ctx)
	if err != nil && t != nil {
		t.Fatalf("cannot evaluate %v: %v", raw, err)
	}
	return v
}

func evalIfResult(raw any, ctx map[string]val) (val, error) {
	if raw == nil {
		return val{kind: kindBool, b: true}, nil
	}
	switch v := raw.(type) {
	case bool:
		return val{kind: kindBool, b: v}, nil
	case string:
		expr := strings.TrimSpace(v)
		expr = strings.TrimPrefix(expr, "${{")
		expr = strings.TrimSuffix(expr, "}}")
		expr = strings.TrimSpace(expr)
		if expr == "" {
			return val{kind: kindBool, b: true}, nil
		}
		p := &parser{s: expr, ctx: ctx}
		out := p.parseOr()
		if p.err != nil {
			return val{kind: kindNull}, fmt.Errorf("%w", p.err)
		}
		if p.i < len(p.s) {
			p.skip()
		}
		if p.i < len(p.s) {
			return val{kind: kindNull}, fmt.Errorf("unparsed tail %q", p.s[p.i:])
		}
		return out, nil
	default:
		return val{kind: kindString, s: fmt.Sprint(v)}, nil
	}
}

func truthy(v val) bool {
	switch v.kind {
	case kindNull:
		return false
	case kindBool:
		return v.b
	case kindNumber:
		return v.n != 0 && v.n == v.n
	case kindString:
		return v.s != ""
	default:
		return false
	}
}

func stringify(v val) string {
	switch v.kind {
	case kindBool:
		if v.b {
			return "true"
		}
		return "false"
	case kindString:
		return v.s
	case kindNumber:
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	default:
		return ""
	}
}

type parser struct {
	s   string
	i   int
	ctx map[string]val
	err error
}

func (p *parser) parseOr() val {
	left := p.parseAnd()
	for p.err == nil && p.peek("||") {
		p.i += 2
		right := p.parseAnd()
		if truthy(left) {
			continue
		}
		left = right
	}
	return left
}

func (p *parser) parseAnd() val {
	left := p.parseCmp()
	for p.err == nil && p.peek("&&") {
		p.i += 2
		right := p.parseCmp()
		if !truthy(left) {
			continue
		}
		left = right
	}
	return left
}

func (p *parser) parseCmp() val {
	left := p.parseUnary()
	if p.err != nil {
		return left
	}
	op := ""
	switch {
	case p.peek("=="):
		op = "=="
	case p.peek("!="):
		op = "!="
	default:
		return left
	}
	p.i += len(op)
	right := p.parseUnary()
	eq := abstractEqual(left, right)
	if op == "!=" {
		eq = !eq
	}
	return val{kind: kindBool, b: eq}
}

func (p *parser) parseUnary() val {
	p.skip()
	if p.peek("!") && !p.peek("!=") {
		p.i++
		v := p.parseUnary()
		return val{kind: kindBool, b: !truthy(v)}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() val {
	p.skip()
	if p.err != nil {
		return val{kind: kindNull}
	}
	if p.i >= len(p.s) {
		p.err = fmt.Errorf("unexpected end")
		return val{kind: kindNull}
	}
	if p.s[p.i] == '(' {
		p.i++
		v := p.parseOr()
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			p.err = fmt.Errorf("missing )")
			return v
		}
		p.i++
		return v
	}
	if p.s[p.i] == '\'' {
		var b strings.Builder
		p.i++
		for p.i < len(p.s) {
			if p.s[p.i] == '\'' {
				if p.i+1 < len(p.s) && p.s[p.i+1] == '\'' {
					b.WriteByte('\'')
					p.i += 2
					continue
				}
				p.i++
				return val{kind: kindString, s: b.String()}
			}
			b.WriteByte(p.s[p.i])
			p.i++
		}
		p.err = fmt.Errorf("unterminated string")
		return val{kind: kindNull}
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			p.i++
			continue
		}
		break
	}
	word := p.s[start:p.i]
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		for p.i < len(p.s) && p.s[p.i] != ')' {
			p.i++
		}
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			p.err = fmt.Errorf("unterminated call %s", word)
			return val{kind: kindNull}
		}
		p.i++
		switch word {
		case "always", "success", "failure":
			// These status functions are true for the steps that follow a
			// successful enterprise setup. failure() is only true after an
			// earlier failure; treating it as true still runs the step.
			return val{kind: kindBool, b: true}
		default:
			p.err = fmt.Errorf("unsupported call %s", word)
			return val{kind: kindNull}
		}
	}
	switch word {
	case "true":
		return val{kind: kindBool, b: true}
	case "false":
		return val{kind: kindBool, b: false}
	case "null":
		return val{kind: kindNull}
	case "":
		p.err = fmt.Errorf("unexpected %q", p.s[p.i:])
		return val{kind: kindNull}
	default:
		if v, ok := p.ctx[word]; ok {
			return v
		}
		return val{kind: kindNull}
	}
}

func (p *parser) peek(op string) bool {
	p.skip()
	return strings.HasPrefix(p.s[p.i:], op)
}

func (p *parser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\n' || p.s[p.i] == '\t') {
		p.i++
	}
}

func abstractEqual(left, right val) bool {
	left, right = coerce(left, right)
	if left.kind != right.kind {
		return false
	}
	switch left.kind {
	case kindNull:
		return true
	case kindBool:
		return left.b == right.b
	case kindString:
		return strings.EqualFold(left.s, right.s)
	case kindNumber:
		if left.n != left.n || right.n != right.n {
			return false
		}
		return left.n == right.n
	default:
		return false
	}
}

func coerce(left, right val) (val, val) {
	if left.kind == right.kind {
		return left, right
	}
	if left.kind == kindNumber && right.kind == kindString {
		right = val{kind: kindNumber, n: parseNumber(right.s)}
		return left, right
	}
	if left.kind == kindString && right.kind == kindNumber {
		left = val{kind: kindNumber, n: parseNumber(left.s)}
		return left, right
	}
	if left.kind == kindBool || left.kind == kindNull {
		left = val{kind: kindNumber, n: asNumber(left)}
		return coerce(left, right)
	}
	if right.kind == kindBool || right.kind == kindNull {
		right = val{kind: kindNumber, n: asNumber(right)}
		return coerce(left, right)
	}
	return left, right
}

func asNumber(v val) float64 {
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
	default:
		return parseNumber(v.s)
	}
}

func parseNumber(s string) float64 {
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return n
}
