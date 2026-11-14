package releaseworkflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	securityMirrorRepo = "grafana/grafana-security-mirror"
	publicRepo         = "grafana/grafana"
	publishPath        = ".github/workflows/publish-artifact.yml"
	releaseBuildPath   = ".github/workflows/release-build.yml"

	// releaseSHA stands in for the commit the security mirror is releasing.
	// It is not a credential and it is not a real object in this clone.
	releaseSHA = "1111111111111111111111111111111111111111"

	patchedRefName = "release-13.0.0#patched"
	runID          = "424242"

	// Audience computed by google-github-actions/auth when audience is unset:
	// https://iam.googleapis.com/ + the workload_identity_provider from
	// grafana/shared-workflows actions/login-to-gcs/action.yaml.
	oidcAudience = "https://iam.googleapis.com/projects/304398677251/locations/global/workloadIdentityPools/github/providers/github-provider"

	placeholderRequestToken = "placeholder-request-token"
	placeholderOIDCJWT      = "placeholder-oidc-jwt"
	attackerStepID          = "attacker-controlled-step"
)

func TestBranchFilterMatchesGitHubExamples(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"feature/*", "feature/my-branch", true},
		{"feature/*", "feature/your-branch", true},
		{"feature/*", "feature/mona/the", false},
		{"feature/**", "feature/beta-a/my-branch", true},
		{"feature/**", "feature/your-branch", true},
		{"feature/**", "feature/mona/the/octocat", true},
		{"main", "main", true},
		{"main", "main-extra", false},
		{"releases/mona-the-octocat", "releases/mona-the-octocat", true},
		{"*", "main", true},
		{"*", "releases", true},
		{"*", "releases/v1", false},
		{"**", "all/the/branches", true},
		{"**", "every/tag", true},
		{"*feature", "mona-feature", true},
		{"*feature", "feature", true},
		{"*feature", "ver-10-feature", true},
		{"v2*", "v2", true},
		{"v2*", "v2.0", true},
		{"v2*", "v2.9", true},
		{"v[12].[0-9]+.[0-9]+", "v1.10.1", true},
		{"v[12].[0-9]+.[0-9]+", "v2.0.0", true},
		{"v[12].[0-9]+.[0-9]+", "v3.0.0", false},
		{"*.jsx?", "page.js", true},
		{"*.jsx?", "page.jsx", true},
		{"docs/**/*.md", "docs/README.md", true},
		{"docs/**/*.md", "docs/mona/hello-world.md", true},
		{"docs/**/*.md", "docs/a/markdown/file.md", true},
		{"release-*.*.*", "release-13.0.0", true},
		{"release-*.*.*", patchedRefName, true},
		{"release-*.*.*", "main", false},
	}
	for _, tc := range cases {
		if got := matchFilter(tc.pattern, tc.name); got != tc.want {
			t.Errorf("matchFilter(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}

	if !endsWithFold("Hello world", "ld") {
		t.Fatal("endsWith example from the expressions reference did not match")
	}
	if !endsWithFold("Release#Patched", "#patched") {
		t.Fatal("endsWith is documented as case-insensitive")
	}
}

func TestSameCommitCallUsesReleaseWorkflowNotPublicMain(t *testing.T) {
	root := repoRoot(t)
	callerPublish := readFile(t, filepath.Join(root, publishPath))
	store := newRefStore()
	store.putCommit(securityMirrorRepo, releaseSHA, publishPath, callerPublish)
	store.putBranch(publicRepo, "main", publishPath, injectAttackerStep(t, callerPublish))

	for _, uses := range []string{
		"./.github/workflows/publish-artifact.yml",
		"$/.github/workflows/publish-artifact.yml",
	} {
		resolved, ref, err := store.resolve(uses, securityMirrorRepo, releaseSHA)
		if err != nil {
			t.Fatalf("%s: %v", uses, err)
		}
		if !bytes.Equal(resolved, callerPublish) {
			t.Fatalf("%s resolved %s, which is not the release commit", uses, ref)
		}
		if bytes.Contains(resolved, []byte(attackerStepID)) {
			t.Fatalf("%s included the public-main step", uses)
		}
	}
}

func TestSecurityMirrorUnpatchedBranchSkipsPublish(t *testing.T) {
	root := repoRoot(t)
	caller := readFile(t, filepath.Join(root, releaseBuildPath))
	wf := parseWorkflow(t, caller)
	ctx := evalContext{
		repository: securityMirrorRepo,
		refName:    "release-13.0.0",
		eventName:  "push",
		runID:      runID,
	}
	if !workflowTriggersOnPush(wf, ctx.refName) {
		t.Fatal("release-13.0.0 is a release branch and still has to match the push filter")
	}
	ran := runnableJobs(t, wf, ctx)
	if ran["setup"] {
		t.Fatal("setup ran for a security-mirror branch that does not end in #patched")
	}
	for _, name := range publishJobNames(t, wf) {
		if ran[name] {
			t.Fatalf("publish job %s ran even though setup was skipped", name)
		}
	}
}

func TestSecurityMirrorPatchedReleasePublishUsesReleaseCommitWorkflow(t *testing.T) {
	root := repoRoot(t)
	callerBuild := readFile(t, filepath.Join(root, releaseBuildPath))
	callerPublish := readFile(t, filepath.Join(root, publishPath))
	publicMain := injectAttackerStep(t, callerPublish)

	store := newRefStore()
	store.putCommit(securityMirrorRepo, releaseSHA, releaseBuildPath, callerBuild)
	store.putCommit(securityMirrorRepo, releaseSHA, publishPath, callerPublish)
	store.putCommit(publicRepo, releaseSHA, publishPath, callerPublish)
	store.putBranch(publicRepo, "main", publishPath, publicMain)

	wf := parseWorkflow(t, callerBuild)
	version := releaseVersion(t, wf, patchedRefName)
	if version != "13.0.0" {
		t.Fatalf("version script produced %q, want 13.0.0", version)
	}

	ctx := evalContext{
		repository: securityMirrorRepo,
		refName:    patchedRefName,
		eventName:  "push",
		runID:      runID,
		version:    version,
	}
	if !workflowTriggersOnPush(wf, ctx.refName) {
		t.Fatal("push of a release branch ending in #patched did not trigger the workflow")
	}
	ran := runnableJobs(t, wf, ctx)
	if !ran["setup"] {
		t.Fatal("setup was skipped for grafana/grafana-security-mirror ref release-13.0.0#patched")
	}

	names := publishJobNames(t, wf)
	if len(names) == 0 {
		t.Fatal("no publish jobs call publish-artifact.yml")
	}

	var mismatches []string
	for _, name := range names {
		if !ran[name] {
			t.Errorf("publish job %s did not run", name)
			continue
		}
		job := wf.jobs[name]
		uses, _ := job["uses"].(string)
		resolved, ref, err := store.resolve(uses, securityMirrorRepo, releaseSHA)
		if err != nil {
			t.Errorf("job %s: %v", name, err)
			continue
		}
		perms := effectivePermissions(job, resolved)
		if perms["id-token"] != "write" {
			t.Errorf("job %s effective id-token permission = %q, want write", name, perms["id-token"])
		}
		inputs := calledInputs(t, job, resolved, ctx)
		if inputs["bucket"] != "grafana-prerelease" || inputs["environment"] != "prod" {
			t.Errorf("job %s upload inputs = bucket %q environment %q", name, inputs["bucket"], inputs["environment"])
		}
		wantPath := version + "_" + runID
		if inputs["bucket-path"] != wantPath {
			t.Errorf("job %s bucket-path = %q, want %q", name, inputs["bucket-path"], wantPath)
		}
		if inputs["service-account"] == "" || !strings.Contains(inputs["service-account"], "github-prerelease-writer@") {
			t.Errorf("job %s service account = %q", name, inputs["service-account"])
		}
		if bytes.Equal(resolved, callerPublish) {
			continue
		}
		mismatches = append(mismatches, fmt.Sprintf(
			"%s resolved %s and ran steps %s (id-token:%s, bucket %s, path %s, service account %s)",
			name, ref, stepIDs(t, resolved), perms["id-token"], inputs["bucket"], inputs["bucket-path"], inputs["service-account"],
		))
	}
	if len(mismatches) == 0 {
		token, audience, authOK := requestOIDCToken(t)
		if !authOK || token != placeholderOIDCJWT || audience != oidcAudience {
			t.Fatalf("release-commit workflow did not obtain the OIDC token the upload action requests (audience %q)", audience)
		}
		return
	}

	token, audience, authOK := requestOIDCToken(t)
	if !authOK || token != placeholderOIDCJWT {
		t.Fatalf("publish jobs loaded a workflow other than the release commit, and the OIDC client could not request a token: %s", strings.Join(mismatches, "; "))
	}
	t.Fatalf("security-mirror publish executed the workflow from public main, and a step in that job obtained an OIDC token (audience %q): %s", audience, strings.Join(mismatches, "; "))
}

type evalContext struct {
	repository string
	refName    string
	eventName  string
	runID      string
	version    string
}

type workflowFile struct {
	on   map[string]any
	jobs map[string]map[string]any
}

func parseWorkflow(t *testing.T, raw []byte) workflowFile {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	on, _ := doc["on"].(map[string]any)
	jobsRaw, _ := doc["jobs"].(map[string]any)
	jobs := make(map[string]map[string]any, len(jobsRaw))
	for name, rawJob := range jobsRaw {
		job, _ := rawJob.(map[string]any)
		jobs[name] = job
	}
	return workflowFile{on: on, jobs: jobs}
}

func workflowTriggersOnPush(wf workflowFile, refName string) bool {
	push, _ := wf.on["push"].(map[string]any)
	patterns, _ := stringList(push["branches"])
	return anyPattern(patterns, refName)
}

func runnableJobs(t *testing.T, wf workflowFile, ctx evalContext) map[string]bool {
	t.Helper()
	state := map[string]string{}
	for len(state) < len(wf.jobs) {
		progress := false
		for name, job := range wf.jobs {
			if _, done := state[name]; done {
				continue
			}
			needs := stringListOrOne(job["needs"])
			ready := true
			skippedDep := false
			for _, need := range needs {
				st, ok := state[need]
				if !ok {
					ready = false
					break
				}
				if st != "success" {
					skippedDep = true
				}
			}
			if !ready {
				continue
			}
			progress = true
			if skippedDep && !strings.Contains(fmt.Sprint(job["if"]), "always()") {
				state[name] = "skipped"
				continue
			}
			if expr, ok := job["if"].(string); ok && strings.TrimSpace(expr) != "" {
				v, err := evalExpr(stripExpr(expr), ctx)
				if err != nil {
					t.Fatalf("job %s if: %v", name, err)
				}
				if !v.truthy() {
					state[name] = "skipped"
					continue
				}
			}
			state[name] = "success"
		}
		if !progress {
			t.Fatalf("could not schedule jobs: %#v", state)
		}
	}
	ran := map[string]bool{}
	for name, st := range state {
		ran[name] = st == "success"
	}
	return ran
}

func publishJobNames(t *testing.T, wf workflowFile) []string {
	t.Helper()
	var names []string
	for name, job := range wf.jobs {
		uses, _ := job["uses"].(string)
		if strings.Contains(uses, "publish-artifact.yml") {
			names = append(names, name)
		}
	}
	if len(names) != 9 {
		t.Fatalf("found %d publish-artifact jobs (%v), want the nine upload jobs", len(names), names)
	}
	return names
}

func releaseVersion(t *testing.T, wf workflowFile, refName string) string {
	t.Helper()
	job := wf.jobs["setup"]
	steps, _ := job["steps"].([]any)
	var script string
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		if step["name"] == "Set up version (Release Branches)" {
			script, _ = step["run"].(string)
		}
	}
	if script == "" {
		t.Fatal("release version script is missing")
	}
	dir := t.TempDir()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REF_NAME="+refName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version script: %v\n%s", err, out)
	}
	version, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		t.Fatalf("VERSION: %v", err)
	}
	return strings.TrimSpace(string(version))
}

func calledInputs(t *testing.T, callerJob map[string]any, called []byte, ctx evalContext) map[string]string {
	t.Helper()
	calledWF := parseWorkflow(t, called)
	var doc map[string]any
	if err := yaml.Unmarshal(called, &doc); err != nil {
		t.Fatalf("parse called workflow: %v", err)
	}
	on, _ := doc["on"].(map[string]any)
	call, _ := on["workflow_call"].(map[string]any)
	inputs, _ := call["inputs"].(map[string]any)
	with, _ := callerJob["with"].(map[string]any)
	out := map[string]string{}
	for name, raw := range inputs {
		spec, _ := raw.(map[string]any)
		if def, ok := spec["default"]; ok {
			out[name] = fmt.Sprint(def)
		}
		if val, ok := with[name]; ok {
			out[name] = interpolate(fmt.Sprint(val), ctx)
		}
	}
	_ = calledWF
	return out
}

func effectivePermissions(callerJob map[string]any, called []byte) map[string]string {
	caller := permissionMap(callerJob["permissions"])
	var doc map[string]any
	if err := yaml.Unmarshal(called, &doc); err != nil {
		return caller
	}
	jobs, _ := doc["jobs"].(map[string]any)
	var calledPerms map[string]string
	specified := false
	for _, raw := range jobs {
		job, _ := raw.(map[string]any)
		if _, ok := job["permissions"]; ok {
			calledPerms = permissionMap(job["permissions"])
			specified = true
			break
		}
	}
	if !specified {
		return caller
	}
	rank := map[string]int{"none": 0, "read": 1, "write": 2}
	out := map[string]string{}
	for key, want := range calledPerms {
		have, ok := caller[key]
		if !ok {
			have = "none"
		}
		if rank[want] > rank[have] {
			want = have
		}
		out[key] = want
	}
	return out
}

func permissionMap(raw any) map[string]string {
	switch v := raw.(type) {
	case map[string]any:
		out := map[string]string{}
		for key, val := range v {
			out[key] = fmt.Sprint(val)
		}
		return out
	default:
		return map[string]string{}
	}
}

func stepIDs(t *testing.T, raw []byte) string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "<unparsed>"
	}
	jobs, _ := doc["jobs"].(map[string]any)
	var ids []string
	for _, rawJob := range jobs {
		job, _ := rawJob.(map[string]any)
		steps, _ := job["steps"].([]any)
		for _, rawStep := range steps {
			step, _ := rawStep.(map[string]any)
			id, _ := step["id"].(string)
			name, _ := step["name"].(string)
			uses, _ := step["uses"].(string)
			switch {
			case id != "":
				ids = append(ids, id)
			case name != "":
				ids = append(ids, name)
			default:
				ids = append(ids, uses)
			}
		}
	}
	return strings.Join(ids, ",")
}

func injectAttackerStep(t *testing.T, original []byte) []byte {
	t.Helper()
	const needle = "    steps:\n"
	insert := needle + "      - name: attacker-controlled-step\n        id: " + attackerStepID + "\n        run: echo ATTACKER_CONTROLLED_UPLOAD\n"
	if !bytes.Contains(original, []byte(needle)) {
		t.Fatal("publish workflow has no steps block to replace")
	}
	out := bytes.Replace(original, []byte(needle), []byte(insert), 1)
	if !bytes.Contains(out, []byte(attackerStepID)) {
		t.Fatal("attacker step was not inserted")
	}
	return out
}

type refStore struct {
	commits  map[string][]byte
	branches map[string][]byte
	tags     map[string][]byte
}

func newRefStore() *refStore {
	return &refStore{
		commits:  map[string][]byte{},
		branches: map[string][]byte{},
		tags:     map[string][]byte{},
	}
}

func refKey(repo, ref, path string) string {
	return repo + "@" + ref + " " + path
}

func (s *refStore) putCommit(repo, sha, path string, data []byte) {
	s.commits[refKey(repo, sha, path)] = append([]byte(nil), data...)
}

func (s *refStore) putBranch(repo, branch, path string, data []byte) {
	s.branches[refKey(repo, branch, path)] = append([]byte(nil), data...)
}

func (s *refStore) resolve(uses, callerRepo, callerSHA string) ([]byte, string, error) {
	if strings.Contains(uses, "${{") {
		return nil, "", fmt.Errorf("uses %q contains an expression", uses)
	}
	if path, ok := sameCommitPath(uses); ok {
		data, ok := s.commits[refKey(callerRepo, callerSHA, path)]
		if !ok {
			return nil, "", fmt.Errorf("missing %s at %s", path, callerSHA)
		}
		return data, callerRepo + "/" + path + "@" + callerSHA, nil
	}
	owner, repo, path, ref, ok := remoteUses(uses)
	if !ok {
		return nil, "", fmt.Errorf("unrecognized uses %q", uses)
	}
	if strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "refs/tags/") {
		return nil, "", fmt.Errorf("uses ref %q uses a refs/ prefix", ref)
	}
	fullRepo := owner + "/" + repo
	if isSHA(ref) {
		data, ok := s.commits[refKey(fullRepo, ref, path)]
		if !ok {
			return nil, "", fmt.Errorf("missing commit %s for %s", ref, path)
		}
		return data, fullRepo + "/" + path + "@" + ref, nil
	}
	if data, ok := s.tags[refKey(fullRepo, ref, path)]; ok {
		return data, fullRepo + "/" + path + "@" + ref, nil
	}
	data, ok := s.branches[refKey(fullRepo, ref, path)]
	if !ok {
		return nil, "", fmt.Errorf("missing branch %s for %s", ref, path)
	}
	return data, fullRepo + "/" + path + "@refs/heads/" + ref, nil
}

func sameCommitPath(uses string) (string, bool) {
	for _, prefix := range []string{"$./.github/workflows/", "$/.github/workflows/", "./.github/workflows/"} {
		if strings.HasPrefix(uses, prefix) && !strings.Contains(uses, "@") {
			return strings.TrimPrefix(uses, strings.TrimSuffix(prefix, ".github/workflows/")), true
		}
	}
	return "", false
}

var remoteUsesPattern = regexp.MustCompile(`^([^/]+)/([^/]+)/(\.github/workflows/.+)@([^@]+)$`)

func remoteUses(uses string) (owner, repo, path, ref string, ok bool) {
	m := remoteUsesPattern.FindStringSubmatch(uses)
	if m == nil {
		return "", "", "", "", false
	}
	return m[1], m[2], m[3], m[4], true
}

func isSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func requestOIDCToken(t *testing.T) (token, audience string, ok bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var gotAuth, gotAudience string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAudience = r.URL.Query().Get("audience")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": placeholderOIDCJWT})
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	dir := t.TempDir()
	install := exec.Command("npm", "install", "--silent", "--no-fund", "--no-audit", "@actions/core@1.11.1")
	install.Dir = dir
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("npm install @actions/core@1.11.1: %v\n%s", err, out)
	}
	script := filepath.Join(dir, "request.js")
	body := []byte(`const core = require("@actions/core");
core.getIDToken(process.env.AUDIENCE).then((token) => {
  process.stdout.write("\nTOKEN:" + token + "\n");
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
`)
	if err := os.WriteFile(script, body, 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	endpoint := "http://" + ln.Addr().String() + "/token?placeholder=1"
	cmd := exec.Command("node", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"AUDIENCE="+oidcAudience,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+placeholderRequestToken,
		"ACTIONS_ID_TOKEN_REQUEST_URL="+endpoint,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("getIDToken: %v\n%s", err, out)
	}
	var got string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "TOKEN:") {
			got = strings.TrimPrefix(line, "TOKEN:")
		}
	}
	authOK := gotAuth == "Bearer "+placeholderRequestToken
	if !authOK {
		t.Fatalf("OIDC request authorization was not the job request token")
	}
	if gotAudience != oidcAudience {
		decoded, _ := url.QueryUnescape(gotAudience)
		if decoded != oidcAudience {
			t.Fatalf("OIDC audience = %q", gotAudience)
		}
		gotAudience = decoded
	}
	return got, gotAudience, true
}

func interpolate(s string, ctx evalContext) string {
	return exprPattern.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "${{"), "}}"))
		v, err := evalExpr(inner, ctx)
		if err != nil {
			return match
		}
		return v.string()
	})
}

var exprPattern = regexp.MustCompile(`\$\{\{.*?\}\}`)

func stripExpr(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		return strings.TrimSpace(s[3 : len(s)-2])
	}
	return s
}

type value struct {
	kind string
	b    bool
	s    string
	n    float64
}

func (v value) truthy() bool {
	switch v.kind {
	case "bool":
		return v.b
	case "num":
		return v.n != 0
	case "string":
		return v.s != ""
	default:
		return false
	}
}

func (v value) string() string {
	switch v.kind {
	case "bool":
		return strconv.FormatBool(v.b)
	case "num":
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	case "string":
		return v.s
	default:
		return ""
	}
}

func evalExpr(src string, ctx evalContext) (value, error) {
	p := &exprParser{s: src}
	v, err := p.parseOr(ctx)
	if err != nil {
		return value{}, err
	}
	p.skip()
	if p.i != len(p.s) {
		return value{}, fmt.Errorf("trailing %q", p.s[p.i:])
	}
	return v, nil
}

type exprParser struct {
	s string
	i int
}

func (p *exprParser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\n' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *exprParser) parseOr(ctx evalContext) (value, error) {
	left, err := p.parseAnd(ctx)
	if err != nil {
		return value{}, err
	}
	for {
		p.skip()
		if !strings.HasPrefix(p.s[p.i:], "||") {
			return left, nil
		}
		p.i += 2
		right, err := p.parseAnd(ctx)
		if err != nil {
			return value{}, err
		}
		left = value{kind: "bool", b: left.truthy() || right.truthy()}
	}
}

func (p *exprParser) parseAnd(ctx evalContext) (value, error) {
	left, err := p.parseUnary(ctx)
	if err != nil {
		return value{}, err
	}
	for {
		p.skip()
		if !strings.HasPrefix(p.s[p.i:], "&&") {
			return left, nil
		}
		p.i += 2
		right, err := p.parseUnary(ctx)
		if err != nil {
			return value{}, err
		}
		left = value{kind: "bool", b: left.truthy() && right.truthy()}
	}
}

func (p *exprParser) parseUnary(ctx evalContext) (value, error) {
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '!' {
		p.i++
		v, err := p.parseUnary(ctx)
		if err != nil {
			return value{}, err
		}
		return value{kind: "bool", b: !v.truthy()}, nil
	}
	return p.parseCmp(ctx)
}

func (p *exprParser) parseCmp(ctx evalContext) (value, error) {
	left, err := p.parsePrimary(ctx)
	if err != nil {
		return value{}, err
	}
	p.skip()
	op := ""
	switch {
	case strings.HasPrefix(p.s[p.i:], "=="):
		op = "=="
	case strings.HasPrefix(p.s[p.i:], "!="):
		op = "!="
	default:
		return left, nil
	}
	p.i += 2
	right, err := p.parsePrimary(ctx)
	if err != nil {
		return value{}, err
	}
	eq := false
	if left.kind == "string" && right.kind == "string" {
		eq = strings.EqualFold(left.s, right.s)
	} else {
		eq = left.string() == right.string()
	}
	if op == "!=" {
		eq = !eq
	}
	return value{kind: "bool", b: eq}, nil
}

func (p *exprParser) parsePrimary(ctx evalContext) (value, error) {
	p.skip()
	if p.i >= len(p.s) {
		return value{}, fmt.Errorf("unexpected end")
	}
	if p.s[p.i] == '(' {
		p.i++
		v, err := p.parseOr(ctx)
		if err != nil {
			return value{}, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return value{}, fmt.Errorf("missing )")
		}
		p.i++
		return v, nil
	}
	if p.s[p.i] == '\'' {
		return p.parseString()
	}
	start := p.i
	for p.i < len(p.s) && (isIdent(p.s[p.i]) || p.s[p.i] == '.') {
		p.i++
	}
	word := p.s[start:p.i]
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		var args []value
		for {
			p.skip()
			if p.i < len(p.s) && p.s[p.i] == ')' {
				p.i++
				break
			}
			arg, err := p.parseOr(ctx)
			if err != nil {
				return value{}, err
			}
			args = append(args, arg)
			p.skip()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ')' {
				p.i++
				break
			}
			return value{}, fmt.Errorf("missing ) after %s", word)
		}
		return callFunc(word, args)
	}
	return lookup(word, ctx)
}

func (p *exprParser) parseString() (value, error) {
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		if p.s[p.i] == '\'' {
			if p.i+1 < len(p.s) && p.s[p.i+1] == '\'' {
				b.WriteByte('\'')
				p.i += 2
				continue
			}
			p.i++
			return value{kind: "string", s: b.String()}, nil
		}
		b.WriteByte(p.s[p.i])
		p.i++
	}
	return value{}, fmt.Errorf("unterminated string")
}

func callFunc(name string, args []value) (value, error) {
	switch name {
	case "endsWith":
		if len(args) != 2 {
			return value{}, fmt.Errorf("endsWith arity")
		}
		return value{kind: "bool", b: endsWithFold(args[0].string(), args[1].string())}, nil
	case "startsWith":
		if len(args) != 2 {
			return value{}, fmt.Errorf("startsWith arity")
		}
		return value{kind: "bool", b: strings.HasPrefix(strings.ToLower(args[0].string()), strings.ToLower(args[1].string()))}, nil
	default:
		return value{}, fmt.Errorf("unsupported function %s", name)
	}
}

func endsWithFold(s, suffix string) bool {
	s, suffix = strings.ToLower(s), strings.ToLower(suffix)
	return strings.HasSuffix(s, suffix)
}

func lookup(path string, ctx evalContext) (value, error) {
	switch path {
	case "github.repository":
		return value{kind: "string", s: ctx.repository}, nil
	case "github.ref_name":
		return value{kind: "string", s: ctx.refName}, nil
	case "github.event_name":
		return value{kind: "string", s: ctx.eventName}, nil
	case "github.run_id":
		return value{kind: "string", s: ctx.runID}, nil
	case "needs.setup.outputs.version":
		return value{kind: "string", s: ctx.version}, nil
	case "true":
		return value{kind: "bool", b: true}, nil
	case "false":
		return value{kind: "bool", b: false}, nil
	default:
		if strings.HasPrefix(path, "needs.") {
			return value{kind: "string", s: ""}, nil
		}
		return value{}, fmt.Errorf("unknown context %s", path)
	}
}

func isIdent(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

func anyPattern(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if matchFilter(pattern, name) {
			return true
		}
	}
	return false
}

func matchFilter(pattern, name string) bool {
	return matchHere(pattern, name)
}

func matchHere(pattern, name string) bool {
	if pattern == "" {
		return name == ""
	}
	if strings.HasPrefix(pattern, "**") {
		rest := pattern[2:]
		if strings.HasPrefix(rest, "/") {
			after := rest[1:]
			if matchHere(after, name) {
				return true
			}
			for i := 0; i < len(name); i++ {
				if name[i] == '/' && matchHere(after, name[i+1:]) {
					return true
				}
			}
			return false
		}
		for i := 0; i <= len(name); i++ {
			if matchHere(rest, name[i:]) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(pattern, "*") {
		rest := pattern[1:]
		for i := 0; i <= len(name); i++ {
			if strings.Contains(name[:i], "/") {
				break
			}
			if matchHere(rest, name[i:]) {
				return true
			}
		}
		return false
	}
	atom, rest, ok := parseAtom(pattern)
	if !ok {
		return false
	}
	min, max := 1, 1
	if strings.HasPrefix(rest, "+") {
		min, max = 1, -1
		rest = rest[1:]
	} else if strings.HasPrefix(rest, "?") {
		min, max = 0, 1
		rest = rest[1:]
	}
	n := 0
	for n < len(name) && (max < 0 || n < max) && atom(name[n]) {
		n++
	}
	for k := n; k >= min; k-- {
		if matchHere(rest, name[k:]) {
			return true
		}
	}
	return false
}

func parseAtom(pattern string) (func(byte) bool, string, bool) {
	if pattern == "" {
		return nil, "", false
	}
	if pattern[0] == '\\' && len(pattern) > 1 {
		c := pattern[1]
		return func(b byte) bool { return b == c }, pattern[2:], true
	}
	if pattern[0] == '[' {
		end := strings.IndexByte(pattern, ']')
		if end < 0 {
			return nil, "", false
		}
		body := pattern[1:end]
		return classMatch(body), pattern[end+1:], true
	}
	c := pattern[0]
	return func(b byte) bool { return b == c }, pattern[1:], true
}

func classMatch(body string) func(byte) bool {
	var want []byte
	for i := 0; i < len(body); i++ {
		if i+2 < len(body) && body[i+1] == '-' {
			for c := body[i]; c <= body[i+2]; c++ {
				want = append(want, c)
			}
			i += 2
			continue
		}
		want = append(want, body[i])
	}
	return func(b byte) bool {
		for _, c := range want {
			if b == c {
				return true
			}
		}
		return false
	}
}

func stringList(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func stringListOrOne(raw any) []string {
	if raw == nil {
		return nil
	}
	if list, ok := stringList(raw); ok {
		return list
	}
	if s, ok := raw.(string); ok {
		return []string{s}
	}
	return nil
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
