package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

const (
	productRepo      = "grafana/grafana"
	attackerMarker   = "ATTACKER-CONTROLLED-WORKFLOW"
	releaseBranch    = "release-9.9.9"
	placeholderToken = "placeholder-not-a-secret"
)

// fullSHA is a full-length commit id. A branch or tag name is not one: tags can move,
// and a branch tip is whatever that ref points at when the job runs.
var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// TestPostReleaseReusableWorkflowsStayOnTheReleaseCommit is the spec for the
// post-release finding. It fails while a privileged job loads a reusable workflow
// from a movable ref, and passes once every such call is pinned to a commit that
// does not move when main does.
func TestPostReleaseReusableWorkflowsStayOnTheReleaseCommit(t *testing.T) {
	product := productRoot(t)
	releaseCommit := git(t, product, "rev-parse", "HEAD")
	entry := filepath.Join(product, ".github", "workflows", "release-comms.yml")

	edges := walkReleaseWorkflows(t, product, releaseCommit)
	if len(edges) == 0 {
		t.Fatal("release-comms.yml has no reusable workflow calls to evaluate")
	}
	assertWalkerSawRawUses(t, edges)
	if _, err := os.Stat(entry); err != nil {
		t.Fatal(err)
	}

	repo := cloneWorkflowTree(t, product)
	moveMain(t, repo)

	for _, event := range []string{"workflow_dispatch", "pull_request_same_repo"} {
		t.Run(event, func(t *testing.T) {
			effects := filepath.Join(t.TempDir(), "effects")
			if err := os.MkdirAll(effects, 0o755); err != nil {
				t.Fatal(err)
			}
			oidc := startOIDCStub(t)
			for i, edge := range edges {
				grant := applyEventPermissions(edge.grant, event)
				if !privileged(grant) {
					continue
				}
				resolved := resolveWorkflow(t, product, repo, edge.callerCommit, edge.uses)
				edgeEffects := filepath.Join(effects, fmt.Sprintf("%02d-%s", i, edge.job))
				if err := os.MkdirAll(edgeEffects, 0o755); err != nil {
					t.Fatal(err)
				}
				runResolvedWorkflow(t, resolved, grant, edgeEffects, oidc)
				assertNoReleaseOrOIDC(t, edgeEffects, event+" "+edge.from+" job "+edge.job+" ("+edge.uses+")")
			}
		})
	}
}

type permSet struct {
	set    bool
	values map[string]string
}

type callEdge struct {
	from          string
	job           string
	uses          string
	callerCommit  string
	callerContent string
	grant         permSet
}

type resolvedWorkflow struct {
	uses    string
	commit  string
	path    string
	content string
	source  string
}

func walkReleaseWorkflows(t *testing.T, product, releaseCommit string) []callEdge {
	t.Helper()
	var edges []callEdge
	seen := map[string]bool{}
	var walk func(commit, path string, cap permSet, capped bool)
	walk = func(commit, path string, cap permSet, capped bool) {
		key := commit + "\x00" + path + "\x00" + cap.key()
		if seen[key] {
			return
		}
		seen[key] = true
		// Nested calls come from the commit the parent ref names. Reading the
		// same path at the release tip would miss a pin that still calls a
		// moving branch from an older commit.
		content := showFile(t, product, commit, path)
		wf := parseWorkflow(t, path, content)
		for jobName, job := range wf.jobs {
			if strings.TrimSpace(job.uses) == "" {
				continue
			}
			grant := job.permissions
			if !grant.set {
				grant = wf.permissions
			}
			if capped {
				grant = downgrade(cap, grant)
			}
			uses := strings.TrimSpace(job.uses)
			edges = append(edges, callEdge{
				from:          path,
				job:           jobName,
				uses:          uses,
				callerCommit:  commit,
				callerContent: content,
				grant:         grant,
			})
			kind, repo, calledPath, ref, ok := splitUses(uses)
			if !ok || kind == "action" || repo != productRepo {
				t.Logf("untested uses %s job %s: %s", path, jobName, uses)
				continue
			}
			next := commit
			if kind != "relative" && fullSHA.MatchString(ref) {
				next = git(t, product, "rev-parse", "--verify", ref+"^{commit}")
			}
			walk(next, calledPath, grant, true)
		}
	}
	walk(releaseCommit, ".github/workflows/release-comms.yml", permSet{}, false)
	return edges
}

func assertWalkerSawRawUses(t *testing.T, edges []callEdge) {
	t.Helper()
	seen := map[string]bool{}
	for _, edge := range edges {
		seen[strings.TrimSpace(edge.uses)] = true
	}
	scanned := map[string]string{}
	for _, edge := range edges {
		scanned[edge.callerCommit+"\x00"+edge.from] = edge.callerContent
	}
	for key, content := range scanned {
		path := strings.SplitN(key, "\x00", 2)[1]
		for _, uses := range mutableWorkflowUses(content) {
			if !seen[uses] {
				t.Errorf("walker did not visit movable reusable workflow %s in %s", uses, path)
			}
		}
	}
}

func mutableWorkflowUses(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		idx := strings.Index(trim, "uses:")
		if idx < 0 {
			continue
		}
		uses := strings.TrimSpace(trim[idx+len("uses:"):])
		uses = strings.Trim(uses, `"'`)
		if i := strings.Index(uses, " #"); i >= 0 {
			uses = strings.TrimSpace(uses[:i])
		}
		if !strings.Contains(uses, ".github/workflows/") || !strings.Contains(uses, "@") {
			continue
		}
		_, _, _, ref, ok := splitUses(uses)
		if !ok || fullSHA.MatchString(ref) {
			continue
		}
		out = append(out, uses)
	}
	return out
}

func cloneWorkflowTree(t *testing.T, product string) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-b", releaseBranch)
	src := filepath.Join(product, ".github", "workflows")
	dst := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "add", ".")
	git(t, repo, "-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "core.hooksPath=/dev/null", "commit", "-m", "release branch workflows")
	git(t, repo, "branch", "main")
	return repo
}

func moveMain(t *testing.T, repo string) {
	t.Helper()
	git(t, repo, "checkout", "main")
	workflows := filepath.Join(repo, ".github", "workflows")
	entries, err := os.ReadDir(workflows)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		if err := os.WriteFile(filepath.Join(workflows, entry.Name()), []byte(attackerWorkflow), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "add", ".")
	git(t, repo, "-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "core.hooksPath=/dev/null", "commit", "-m", "change workflows on main")
	// The release branch stays on the commit from before this push.
	if git(t, repo, "rev-parse", releaseBranch) == git(t, repo, "rev-parse", "main") {
		t.Fatal("main did not move away from the release branch")
	}
}

const attackerWorkflow = `# ` + attackerMarker + `
name: attacker
on:
  workflow_call:
permissions: {}
jobs:
  main:
    permissions:
      contents: write
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - name: publish release or request an OIDC token
        run: |
          set -eu
          if [ "${CONTENTS_PERMISSION}" = "write" ]; then
            printf 'release-created\n' >> "${EFFECT_DIR}/releases"
          fi
          if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
            curl -fsS \
              -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
              "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=placeholder-audience" \
              -o "${EFFECT_DIR}/oidc-token"
          fi
`

func resolveWorkflow(t *testing.T, product, movedRepo, callerCommit, uses string) resolvedWorkflow {
	t.Helper()
	kind, repo, path, ref, ok := splitUses(uses)
	if !ok || kind == "action" || repo != productRepo {
		t.Fatalf("cannot resolve %s", uses)
	}
	out := resolvedWorkflow{uses: strings.TrimSpace(uses), path: path}
	if kind == "relative" {
		// A ./ or $/ call is the caller commit, not the default branch.
		out.commit = callerCommit
		out.source = product
		out.content = showFile(t, product, callerCommit, path)
		return out
	}
	if fullSHA.MatchString(ref) {
		out.commit = git(t, product, "rev-parse", "--verify", ref+"^{commit}")
		out.source = product
		out.content = showFile(t, product, out.commit, path)
		return out
	}
	// Branch and tag names are resolved when the job runs. A tag wins when both exist.
	if commit, ok := resolveRef(movedRepo, "refs/tags/"+ref); ok {
		out.commit = commit
	} else if commit, ok := resolveRef(movedRepo, "refs/heads/"+ref); ok {
		out.commit = commit
	} else {
		t.Fatalf("movable ref %q in %s did not resolve", ref, uses)
	}
	out.source = movedRepo
	out.content = showFile(t, movedRepo, out.commit, path)
	return out
}

func resolveRef(repo, ref string) (string, bool) {
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", "--quiet", ref)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func runResolvedWorkflow(t *testing.T, resolved resolvedWorkflow, cap permSet, effects string, oidc *httptest.Server) {
	t.Helper()
	if !strings.Contains(resolved.content, attackerMarker) {
		return
	}
	wf := parseWorkflow(t, resolved.path, resolved.content)
	for jobName, job := range wf.jobs {
		grant := job.permissions
		if !grant.set {
			grant = wf.permissions
		}
		effective := downgrade(cap, grant)
		for _, step := range job.steps {
			script := strings.TrimSpace(step.run)
			if script == "" {
				continue
			}
			cmd := exec.Command("bash", "-eu", "-c", script)
			cmd.Env = append(os.Environ(),
				"EFFECT_DIR="+effects,
				"CONTENTS_PERMISSION="+effective.get("contents"),
			)
			// id-token: write is what makes the OIDC request URL exist.
			if effective.get("id-token") == "write" {
				sum := sha256.Sum256([]byte(resolved.uses + "\x00" + jobName))
				cmd.Env = append(cmd.Env,
					"ACTIONS_ID_TOKEN_REQUEST_URL="+oidc.URL+"/token?",
					"ACTIONS_ID_TOKEN_REQUEST_TOKEN=placeholder-request-"+hex.EncodeToString(sum[:4]),
				)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("resolved %s at %s job %s: %v\n%s", resolved.uses, resolved.commit, jobName, err, out)
			}
		}
	}
}

func startOIDCStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"` + placeholderToken + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func assertNoReleaseOrOIDC(t *testing.T, effects, event string) {
	t.Helper()
	releasePath := filepath.Join(effects, "releases")
	oidcPath := filepath.Join(effects, "oidc-token")
	if body, err := os.ReadFile(releasePath); err == nil {
		t.Errorf("%s: moving main published a release (%s)", event, strings.TrimSpace(string(body)))
	}
	if body, err := os.ReadFile(oidcPath); err == nil {
		if !strings.Contains(string(body), placeholderToken) {
			t.Errorf("%s: OIDC stub returned unexpected body", event)
		}
		t.Errorf("%s: moving main obtained an OIDC token for the release job", event)
	}
}

func applyEventPermissions(grant permSet, event string) permSet {
	// pull_request from a fork drops write scopes. A release PR opened in this
	// repository, and workflow_dispatch, keep the permissions written on the job.
	if event != "pull_request_fork" {
		return grant
	}
	out := grant.clone()
	for scope, level := range out.values {
		if level == "write" && scope != "id-token" {
			out.values[scope] = "read"
		}
		if scope == "id-token" && level == "write" {
			out.values[scope] = "none"
		}
	}
	return out
}

func privileged(grant permSet) bool {
	return grant.get("contents") == "write" || grant.get("id-token") == "write"
}

func downgrade(cap, requested permSet) permSet {
	if !requested.set {
		return cap
	}
	out := permSet{set: true, values: map[string]string{}}
	keys := map[string]struct{}{}
	for scope := range cap.values {
		keys[scope] = struct{}{}
	}
	for scope := range requested.values {
		keys[scope] = struct{}{}
	}
	for scope := range keys {
		out.values[scope] = minLevel(cap.get(scope), requested.get(scope))
	}
	return out
}

func minLevel(a, b string) string {
	rank := map[string]int{"none": 0, "": 0, "read": 1, "write": 2}
	if rank[a] < rank[b] {
		return normalizeLevel(a)
	}
	return normalizeLevel(b)
}

func normalizeLevel(level string) string {
	switch level {
	case "read", "write":
		return level
	default:
		return "none"
	}
}

type workflowFile struct {
	permissions permSet
	jobs        map[string]workflowJob
}

type workflowJob struct {
	permissions permSet
	uses        string
	steps       []workflowStep
}

type workflowStep struct {
	run string
}

func parseWorkflow(t *testing.T, path, content string) workflowFile {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	doc := root.Content[0]
	wf := workflowFile{jobs: map[string]workflowJob{}}
	for i := 0; i < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		val := doc.Content[i+1]
		switch key {
		case "permissions":
			wf.permissions = decodePerms(val)
		case "jobs":
			for j := 0; j < len(val.Content); j += 2 {
				jobName := val.Content[j].Value
				wf.jobs[jobName] = decodeJob(val.Content[j+1])
			}
		}
	}
	return wf
}

func decodeJob(node *yaml.Node) workflowJob {
	job := workflowJob{}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "permissions":
			job.permissions = decodePerms(val)
		case "uses":
			job.uses = val.Value
		case "steps":
			for _, step := range val.Content {
				job.steps = append(job.steps, decodeStep(step))
			}
		}
	}
	return job
}

func decodeStep(node *yaml.Node) workflowStep {
	step := workflowStep{}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "run" {
			step.run = node.Content[i+1].Value
		}
	}
	return step
}

func decodePerms(node *yaml.Node) permSet {
	perms := permSet{set: true, values: map[string]string{}}
	if node.Kind == yaml.ScalarNode {
		switch node.Value {
		case "read-all":
			for _, scope := range []string{"contents", "id-token"} {
				if scope == "id-token" {
					perms.values[scope] = "none"
					continue
				}
				perms.values[scope] = "read"
			}
		case "write-all":
			perms.values["contents"] = "write"
			perms.values["id-token"] = "write"
		}
		return perms
	}
	for i := 0; i < len(node.Content); i += 2 {
		perms.values[node.Content[i].Value] = node.Content[i+1].Value
	}
	return perms
}

func (p permSet) get(scope string) string {
	if !p.set {
		return "none"
	}
	return normalizeLevel(p.values[scope])
}

func (p permSet) clone() permSet {
	out := permSet{set: p.set, values: map[string]string{}}
	for scope, level := range p.values {
		out.values[scope] = level
	}
	return out
}

func (p permSet) key() string {
	if !p.set {
		return "-"
	}
	return p.get("contents") + "/" + p.get("id-token")
}

func splitUses(uses string) (kind, repo, path, ref string, ok bool) {
	uses = strings.TrimSpace(uses)
	uses = strings.Trim(uses, `"'`)
	switch {
	case strings.HasPrefix(uses, "./"):
		path = strings.TrimPrefix(uses, "./")
		if !strings.HasPrefix(path, ".github/workflows/") {
			return "", "", "", "", false
		}
		return "relative", productRepo, path, "", true
	case strings.HasPrefix(uses, "$/"):
		path = strings.TrimPrefix(uses, "$/")
		if !strings.HasPrefix(path, ".github/workflows/") {
			return "", "", "", "", false
		}
		return "relative", productRepo, path, "", true
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 {
		return "", "", "", "", false
	}
	ref = uses[at+1:]
	rest := uses[:at]
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		return "", "", "", "", false
	}
	repo = parts[0] + "/" + parts[1]
	path = parts[2]
	if strings.HasPrefix(path, ".github/workflows/") {
		return "workflow", repo, path, ref, true
	}
	return "action", repo, path, ref, true
}

func showFile(t *testing.T, repo, commit, path string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "show", commit+":"+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git show %s:%s: %v", commit, path, err)
	}
	return string(out)
}

func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func productRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
