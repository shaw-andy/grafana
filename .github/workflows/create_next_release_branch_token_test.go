package workflows

import (
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

	"gopkg.in/yaml.v2"
)

// placeholderWriterToken is not a credential. It stands in for the installation
// token minted by create-github-app-token and forwarded to bump-release.
const placeholderWriterToken = "placeholder-writer-token"

const attackerRef = "refs/heads/attacker-controlled"

var fullCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses        string            `yaml:"uses"`
	With        map[string]string `yaml:"with"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]string `yaml:"with"`
}

type compositeAction struct {
	Runs struct {
		Steps []struct {
			Env map[string]string `yaml:"env"`
			Run string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func TestWriterTokenDoesNotReachMovingBumpRelease(t *testing.T) {
	workflowPath := workflowPath(t, "create-next-release-branch.yml")
	workflow := loadWorkflow(t, workflowPath)
	job, ok := workflow.Jobs["main"]
	if !ok {
		t.Fatal("create-next-release-branch.yml has no main job")
	}
	if job.Permissions["contents"] != "read" {
		t.Fatalf("job permissions contents = %q, want read so the default token cannot create branches", job.Permissions["contents"])
	}

	config := findStep(t, job, "app-config")
	release := findStep(t, job, "branch")
	tokenExpr, wired := release.With["token"]
	if !wired || !strings.Contains(tokenExpr, "steps.get-github-app-token.outputs.token") {
		// The writer installation token is not forwarded to bump-release.
		return
	}

	ownerRepos := callerOwnerRepos(t)
	for _, ownerRepo := range ownerRepos {
		for _, refName := range []string{"main", "release-11.2.3"} {
			app, permissionSet := runAppConfig(t, config, ownerRepo, refName)
			wantApp := "grafana-writer"
			wantScope := "grafana"
			if ownerRepo == "grafana/grafana-enterprise" {
				wantApp = "grafana-enterprise-writer"
				wantScope = "enterprise"
			}
			if app != wantApp {
				t.Fatalf("ownerRepo %s ref %s selected app %q, want %s", ownerRepo, refName, app, wantApp)
			}
			tier := "main"
			if strings.HasPrefix(refName, "release-") {
				tier = "release"
			}
			wantSet := "writer-" + wantScope + "-" + tier
			if permissionSet != wantSet {
				t.Fatalf("ownerRepo %s ref %s selected permission set %q, want %s", ownerRepo, refName, permissionSet, wantSet)
			}
		}
	}
	if _, err := runAppConfigResult(t, config, "unrelated/repo", "main"); err == nil {
		t.Fatal("ownerRepo unrelated/repo was accepted")
	}

	actionName, actionRef := splitUses(t, release.Uses)
	if actionName != "grafana/grafana-github-actions-go/bump-release" {
		t.Fatalf("release step uses %q", release.Uses)
	}

	if fullCommitSHA.MatchString(actionRef) {
		assertCommitExists(t, "grafana/grafana-github-actions-go", actionRef)
		assertSHAPinDoesNotFollowBranch(t, actionRef)
		return
	}

	for _, ownerRepo := range ownerRepos {
		ownerRepo := ownerRepo
		t.Run(ownerRepo, func(t *testing.T) {
			created := runMovedAction(t, "bump-release", actionRef, ownerRepo)
			for _, ref := range created {
				if ref == attackerRef {
					t.Fatalf("uses ref %q is not a commit SHA; the commit at that ref received %s and created %s in %s", actionRef, tokenExpr, attackerRef, ownerRepo)
				}
			}
			t.Fatalf("uses ref %q resolved to the moving branch tip, which is not named in the workflow", actionRef)
		})
	}
}

func TestWriterTokenStepsUsePinnedActions(t *testing.T) {
	entries, err := os.ReadDir(filepath.Dir(workflowPath(t, "create-next-release-branch.yml")))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		workflow := loadWorkflow(t, workflowPath(t, name))
		for jobName, job := range workflow.Jobs {
			for i, step := range job.Steps {
				if !stepPassesWriterToken(job, step) {
					continue
				}
				repo, actionDir, ref, ok := parseUses(step.Uses)
				if !ok {
					continue
				}
				label := fmt.Sprintf("%s/%s/%d", name, jobName, i)
				if fullCommitSHA.MatchString(ref) {
					assertCommitExists(t, repo, ref)
					assertSHAPinDoesNotFollowBranch(t, ref)
					continue
				}
				t.Run(label, func(t *testing.T) {
					created := runMovedAction(t, actionDir, ref, "grafana/grafana")
					for _, got := range created {
						if got == attackerRef {
							t.Fatalf("%s passes a writer token to %s, and the commit at that ref created %s", label, step.Uses, attackerRef)
						}
					}
					t.Fatalf("%s passes a writer token to moving ref %s", label, step.Uses)
				})
			}
		}
	}
}

func stepPassesWriterToken(job workflowJob, step workflowStep) bool {
	if step.Uses == "" || strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, "docker://") {
		return false
	}
	values := []string{}
	for _, value := range step.With {
		values = append(values, value)
	}
	for _, value := range step.Env {
		values = append(values, value)
	}
	for _, value := range values {
		id := referencedTokenStep(value)
		if id == "" {
			continue
		}
		for _, candidate := range job.Steps {
			if candidate.ID != id {
				continue
			}
			if jobMintsWriterToken(job, candidate) {
				return true
			}
		}
	}
	return false
}

func referencedTokenStep(value string) string {
	const marker = "steps."
	start := strings.Index(value, marker)
	if start < 0 {
		return ""
	}
	rest := value[start+len(marker):]
	id, _, ok := strings.Cut(rest, ".outputs.token")
	if !ok || id == "" || strings.Contains(id, " ") {
		return ""
	}
	return id
}

func jobMintsWriterToken(job workflowJob, tokenStep workflowStep) bool {
	blob := tokenStep.With["github_app"] + "\n" + tokenStep.With["permission_set"]
	if writerSelector(blob) {
		return true
	}
	if !strings.Contains(blob, "app-config.outputs") {
		return false
	}
	for _, step := range job.Steps {
		if step.ID == "app-config" && writerSelector(step.Run) {
			return true
		}
	}
	return false
}

func writerSelector(value string) bool {
	if strings.Contains(value, "pr-writer") && !strings.Contains(value, "release-writer") && !strings.Contains(value, "grafana-writer") {
		return false
	}
	for _, needle := range []string{
		"grafana-writer",
		"grafana-enterprise-writer",
		"grafana-security-mirror-writer",
		"release-writer",
		"writer-grafana",
		"writer-enterprise",
		"writer-security-mirror",
		"permission_set=writer-",
	} {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func parseUses(uses string) (repo, actionDir, ref string, ok bool) {
	uses = strings.TrimSpace(uses)
	name, ref, found := strings.Cut(uses, "@")
	if !found || strings.Contains(ref, "@") || ref == "" {
		return "", "", "", false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	repo = parts[0] + "/" + parts[1]
	if len(parts) > 2 {
		actionDir = strings.Join(parts[2:], "/")
	}
	return repo, actionDir, ref, true
}

func callerOwnerRepos(t *testing.T) []string {
	t.Helper()
	callers := loadWorkflow(t, workflowPath(t, "release-comms.yml"))
	var repos []string
	seen := map[string]bool{}
	for _, job := range callers.Jobs {
		if !strings.Contains(job.Uses, "create-next-release-branch.yml") {
			continue
		}
		repo := job.With["ownerRepo"]
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	if len(repos) != 2 || !seen["grafana/grafana"] || !seen["grafana/grafana-enterprise"] {
		t.Fatalf("release-comms.yml ownerRepo inputs = %v, want grafana/grafana and grafana/grafana-enterprise", repos)
	}
	return repos
}

func runMovedAction(t *testing.T, actionDir, usesRef, ownerRepo string) []string {
	t.Helper()
	actionRepo := t.TempDir()
	git(t, actionRepo, "init")
	git(t, actionRepo, "config", "user.email", "test@example.com")
	git(t, actionRepo, "config", "user.name", "test")

	manifest := writeAction(t, actionRepo, actionDir, benignRunScript)
	git(t, actionRepo, "add", manifest)
	git(t, actionRepo, "commit", "-m", "benign action")
	git(t, actionRepo, "branch", "-M", usesRef)

	writeAction(t, actionRepo, actionDir, attackerRunScript)
	git(t, actionRepo, "add", manifest)
	git(t, actionRepo, "commit", "-m", "changed action keeps token input")
	attackerCommit := strings.TrimSpace(git(t, actionRepo, "rev-parse", "HEAD"))

	resolved := resolveUsesRef(t, actionRepo, usesRef)
	if fullCommitSHA.MatchString(usesRef) && resolved == attackerCommit {
		t.Fatalf("pinned ref %s resolved to the commit added on the branch after the pin", usesRef)
	}

	target := t.TempDir()
	git(t, target, "init")
	git(t, target, "config", "user.email", "test@example.com")
	git(t, target, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(target, "README"), []byte("target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, target, "add", "README")
	git(t, target, "commit", "-m", "initial")
	targetSHA := strings.TrimSpace(git(t, target, "rev-parse", "HEAD"))

	var created []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/repos/" + ownerRepo + "/git/refs"
		if r.Method != http.MethodPost || r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		// go-github NewTokenClient uses oauth2, which sets Authorization to
		// "Bearer" plus the access token (oauth2 Token.Type and SetAuthHeader).
		if r.Header.Get("Authorization") != "Bearer "+placeholderWriterToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Ref == "" || body.SHA == "" {
			http.Error(w, "missing ref", http.StatusBadRequest)
			return
		}
		git(t, target, "update-ref", body.Ref, body.SHA)
		created = append(created, body.Ref)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"ref":%q,"object":{"sha":%q}}`, body.Ref, body.SHA)
	}))
	t.Cleanup(server.Close)

	checkout := t.TempDir()
	git(t, checkout, "init")
	git(t, checkout, "fetch", actionRepo, resolved)
	git(t, checkout, "checkout", "FETCH_HEAD")

	action := loadComposite(t, filepath.Join(checkout, actionDir, "action.yml"))
	if len(action.Runs.Steps) != 1 || action.Runs.Steps[0].Run == "" {
		t.Fatalf("resolved action at %s has no run step", resolved)
	}
	env := evaluateActionEnv(action.Runs.Steps[0].Env, map[string]string{
		"token": placeholderWriterToken,
	})
	if env["GITHUB_TOKEN"] != placeholderWriterToken {
		t.Fatalf("resolved action did not receive the writer token in GITHUB_TOKEN (got %q)", env["GITHUB_TOKEN"])
	}

	script, err := os.CreateTemp(t.TempDir(), "action-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(script, action.Runs.Steps[0].Run); err != nil {
		t.Fatal(err)
	}
	script.Close()

	cmd := exec.Command("bash", script.Name())
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GITHUB_API_URL=" + server.URL,
		"OWNER_REPO=" + ownerRepo,
		"TARGET_SHA=" + targetSHA,
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("action at %s failed: %v\n%s", resolved, err, out)
	}
	if resolved != attackerCommit {
		t.Fatalf("moving ref %q resolved to %s, not the commit added on the branch (%s)", usesRef, resolved, attackerCommit)
	}
	return created
}

func resolveUsesRef(t *testing.T, repo, ref string) string {
	t.Helper()
	if fullCommitSHA.MatchString(ref) {
		return strings.TrimSpace(git(t, repo, "rev-parse", "--verify", ref+"^{commit}"))
	}
	// A branch or tag ref is the name the runner sends to the Actions service.
	// Git resolves that name to the current tip; a later commit on the branch
	// changes the result. A full SHA does not.
	return strings.TrimSpace(git(t, repo, "rev-parse", "--verify", "refs/heads/"+ref))
}

func assertSHAPinDoesNotFollowBranch(t *testing.T, pinned string) {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(repo, "file"), []byte("pinned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "file")
	git(t, repo, "commit", "-m", "pinned")
	first := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(repo, "file"), []byte("moved\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "file")
	git(t, repo, "commit", "-m", "moved main")
	tip := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	if first == tip {
		t.Fatal("fixture branch did not move")
	}
	// The pin under test is an upstream SHA, so it cannot equal this fixture tip.
	// Resolving a SHA asks git for that object; resolving the branch name asks
	// for the tip. Those stay different after the branch moves.
	got := strings.TrimSpace(git(t, repo, "rev-parse", "--verify", first+"^{commit}"))
	if got != first || got == tip || pinned == tip {
		t.Fatalf("SHA pin followed the branch: pin %s object %s tip %s", pinned, got, tip)
	}
}

func assertCommitExists(t *testing.T, repo, sha string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init")
	cmd := exec.Command("git", "fetch", "--depth=1", "https://github.com/"+repo+".git", sha)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pinned SHA %s is not a commit in %s: %v\n%s", sha, repo, err, out)
	}
	got := strings.TrimSpace(git(t, dir, "rev-parse", "FETCH_HEAD"))
	if !strings.EqualFold(got, sha) {
		t.Fatalf("pinned SHA %s resolved to %s", sha, got)
	}
}

func evaluateActionEnv(env, inputs map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for key, value := range env {
		out[key] = value
		for name, input := range inputs {
			value = strings.ReplaceAll(value, "${{ inputs."+name+" }}", input)
			value = strings.ReplaceAll(value, "${{inputs."+name+"}}", input)
		}
		out[key] = value
	}
	return out
}

func runAppConfig(t *testing.T, step workflowStep, ownerRepo, refName string) (string, string) {
	t.Helper()
	out, err := runAppConfigResult(t, step, ownerRepo, refName)
	if err != nil {
		t.Fatalf("app-config for %s at %s: %v\n%s", ownerRepo, refName, err, out)
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	if values["github_app"] == "" || values["permission_set"] == "" {
		t.Fatalf("app-config output = %q", out)
	}
	return values["github_app"], values["permission_set"]
}

func runAppConfigResult(t *testing.T, step workflowStep, ownerRepo, refName string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "app-config.sh")
	if err := os.WriteFile(script, []byte(step.Run), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "github-output")
	cmd := exec.Command("bash", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_OUTPUT=" + output}
	for key, value := range step.Env {
		switch {
		case strings.Contains(value, "inputs.ownerRepo"):
			value = ownerRepo
		case strings.Contains(value, "github.ref_name"):
			value = refName
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	raw, err := cmd.CombinedOutput()
	data, readErr := os.ReadFile(output)
	if readErr != nil && err == nil {
		return string(raw), readErr
	}
	if err != nil {
		return string(data), err
	}
	return string(data), nil
}

func writeAction(t *testing.T, repo, actionDir, runScript string) string {
	t.Helper()
	dir := repo
	rel := "action.yml"
	if actionDir != "" {
		dir = filepath.Join(repo, actionDir)
		rel = filepath.Join(actionDir, "action.yml")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: Bump Release Branch\ninputs:\n  token:\n    required: true\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        GITHUB_TOKEN: ${{ inputs.token }}\n      run: |\n"
	for _, line := range strings.Split(strings.TrimRight(runScript, "\n"), "\n") {
		manifest += "        " + line + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return rel
}

const attackerRunScript = `set -euo pipefail
curl -sS -f -X POST \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  --data "{\"ref\":\"refs/heads/attacker-controlled\",\"sha\":\"${TARGET_SHA}\"}" \
  "${GITHUB_API_URL}/repos/${OWNER_REPO}/git/refs"
`

const benignRunScript = `set -euo pipefail
exit 0
`

func loadComposite(t *testing.T, path string) compositeAction {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var action compositeAction
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	return action
}

func findStep(t *testing.T, job workflowJob, id string) workflowStep {
	t.Helper()
	for _, step := range job.Steps {
		if step.ID == id {
			return step
		}
	}
	t.Fatalf("step %s not found", id)
	return workflowStep{}
}

func splitUses(t *testing.T, uses string) (string, string) {
	t.Helper()
	uses = strings.TrimSpace(uses)
	name, ref, ok := strings.Cut(uses, "@")
	if !ok || name == "" || ref == "" || strings.Contains(ref, "@") {
		t.Fatalf("uses %q is not org/repo[/path]@ref", uses)
	}
	return name, ref
}

func loadWorkflow(t *testing.T, path string) workflowFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowFile
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func workflowPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Join(filepath.Dir(file), name)
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
