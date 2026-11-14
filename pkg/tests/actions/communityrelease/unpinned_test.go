package communityrelease

import (
	"encoding/json"
	"fmt"
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

// placeholderForumKey is the vault value these tests use. It is not a credential.
const placeholderForumKey = "placeholder-forum-key"

const (
	placeholderOIDCRequestToken = "placeholder-oidc-request-token"
	placeholderOIDCJWT          = "placeholder-oidc-jwt"
	placeholderVaultToken       = "placeholder-vault-token"
	placeholderGitHubToken      = "placeholder-github-token"
)

// fullSHA matches the commit id the runner treats as an immutable action ref.
// ActionManager downloads the ResolvedSha it was given and will not follow a branch
// that later moves. A 40-hex ref is that commit id; any other ref is resolved with
// git rev-parse at job time, which is the branch tip after a force-push or a new commit.
var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func TestCommunityReleaseDoesNotGiveForumKeyToMovedMain(t *testing.T) {
	h := newHarness(t)
	got := h.run(t, readWorkflow(t))
	assertForumKeyStaysOffMovedMain(t, got)
}

func TestPinnedSHARunsThatCommitInsteadOfMovedMain(t *testing.T) {
	h := newHarness(t)
	// Own workflow, not a rewrite of the file under test, so pinning that file does not change this case.
	raw := fmt.Sprintf(`
jobs:
  main:
    permissions:
      id-token: write
      contents: read
    steps:
      - id: vault-secrets
        uses: grafana/shared-workflows/actions/get-vault-secrets@%s
        with:
          repo_secrets: |
            GRAFANABOT_FORUM_KEY=community_release:GRAFANABOT_FORUM_KEY
      - uses: grafana/grafana-github-actions-go/community-release@%s
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          version: ${{ inputs.version }}
          community_api_key: ${{ fromJSON(steps.vault-secrets.outputs.secrets).GRAFANABOT_FORUM_KEY }}
          community_api_username: grafanabot
          dry_run: ${{ inputs.dry_run }}
`, h.vault.benignSHA, h.release.benignSHA)

	got := h.run(t, raw)
	assertForumKeyStaysOffMovedMain(t, got)
	if !strings.Contains(readFile(t, h.vault.benignMarker), "benign-ran") {
		t.Fatal("pinned get-vault-secrets commit did not run")
	}
	if !strings.Contains(readFile(t, h.release.benignMarker), "benign-ran") {
		t.Fatal("pinned community-release commit did not run")
	}
}

func TestUnknownFullSHADoesNotRunMovedMain(t *testing.T) {
	h := newHarness(t)
	raw := readWorkflow(t)
	const unknown = "0123456789abcdef0123456789abcdef01234567"
	raw = strings.ReplaceAll(raw, "get-vault-secrets@main", "get-vault-secrets@"+unknown)
	raw = strings.ReplaceAll(raw, "community-release@main", "community-release@"+unknown)

	got := h.run(t, raw)
	assertForumKeyStaysOffMovedMain(t, got)
	if _, err := os.Stat(h.vault.attackerCapture); err == nil {
		t.Fatal("moved get-vault-secrets main ran for a full commit SHA")
	}
	if _, err := os.Stat(h.release.attackerCapture); err == nil {
		t.Fatal("moved community-release main ran for a full commit SHA")
	}
}

func assertForumKeyStaysOffMovedMain(t *testing.T, got runResult) {
	t.Helper()
	var leaked []string
	for _, cap := range got.movedMain {
		if strings.Contains(cap.body, placeholderForumKey) {
			leaked = append(leaked, cap.uses)
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("actions resolved from a moved main branch received the forum key: %s", strings.Join(leaked, ", "))
	}
}

type runResult struct {
	movedMain []capture
}

type capture struct {
	uses string
	body string
}

type harness struct {
	vault    *actionRepo
	release  *actionRepo
	oidcURL  string
	vaultURL string
	forumKey string
}

type actionRepo struct {
	dir             string
	benignSHA       string
	benignMarker    string
	attackerCapture string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	srv := newVaultOIDCServer(t, placeholderForumKey)
	h := &harness{
		vaultURL: srv.URL,
		oidcURL:  srv.URL + "/oidc?",
		forumKey: placeholderForumKey,
	}
	h.vault = initActionRepo(t, "actions/get-vault-secrets", func(marker, capture string) (benign, attacker string) {
		return benignManifest(marker), vaultAttackerManifest(capture, srv.URL)
	})
	h.release = initActionRepo(t, "community-release", func(marker, capture string) (benign, attacker string) {
		return benignManifest(marker), releaseAttackerManifest(capture)
	})
	if h.vault.benignSHA == h.vault.attackerTip(t) {
		t.Fatal("get-vault-secrets main did not move")
	}
	if h.release.benignSHA == h.release.attackerTip(t) {
		t.Fatal("community-release main did not move")
	}
	return h
}

func (r *actionRepo) attackerTip(t *testing.T) string {
	t.Helper()
	return gitRevParse(t, r.dir, "refs/heads/main")
}

func newVaultOIDCServer(t *testing.T, forumKey string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// OidcClient.getIDToken reads ACTIONS_ID_TOKEN_REQUEST_URL and sends the request token.
	// hashicorp/vault-action auth.js then posts that jwt to v1/auth/<path>/login.
	mux.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+placeholderOIDCRequestToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": placeholderOIDCJWT})
	})
	mux.HandleFunc("/v1/auth/github-actions-oidc/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			JWT  string `json:"jwt"`
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.JWT != placeholderOIDCJWT || body.Role != "vault-github-actions" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": placeholderVaultToken},
		})
	})
	mux.HandleFunc("/v1/ci/data/repo/grafana/grafana/community_release", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != placeholderVaultToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]string{"GRAFANABOT_FORUM_KEY": forumKey},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func initActionRepo(t *testing.T, actionPath string, manifests func(marker, capture string) (benign, attacker string)) *actionRepo {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "benign")
	capture := filepath.Join(t.TempDir(), "attacker")
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "test")

	benign, attacker := manifests(marker, capture)
	writeAction(t, dir, actionPath, benign)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "benign")
	benignSHA := gitRevParse(t, dir, "HEAD")

	writeAction(t, dir, actionPath, attacker)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "move main")

	return &actionRepo{dir: dir, benignSHA: benignSHA, benignMarker: marker, attackerCapture: capture}
}

func benignManifest(marker string) string {
	return marshalManifest(tManifest{
		Name: "benign",
		Runs: tRuns{
			Using: "composite",
			Steps: []tStep{{
				Shell: "bash",
				Run:   fmt.Sprintf("printf '%%s\\n' benign-ran >> %q\n", marker),
			}},
		},
	})
}

func vaultAttackerManifest(capture, vaultURL string) string {
	// The moved main commit keeps repo_secrets and requests the same OIDC token and
	// Vault path the pinned action would. The script records the value Vault returns.
	script := fmt.Sprintf(`python3 - <<'PY'
import json, os, urllib.parse, urllib.request, urllib.error
line = os.environ.get("REPO_SECRETS", "").split()
if not line:
    raise SystemExit(0)
name, rest = line[0].split("=", 1)
secret_path, secret_key = rest.split(":", 1)
repo = os.environ["GITHUB_REPOSITORY"]
vault_path = "ci/data/repo/{}/{}".format(repo, secret_path)
req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote("https://vault-github-actions.grafana-ops.net")
req = urllib.request.Request(req_url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
with urllib.request.urlopen(req) as resp:
    jwt = json.load(resp)["value"]
login_body = json.dumps({"jwt": jwt, "role": "vault-github-actions"}).encode()
login = urllib.request.Request(%q + "/v1/auth/github-actions-oidc/login", data=login_body, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(login) as resp:
    token = json.load(resp)["auth"]["client_token"]
get = urllib.request.Request(%q + "/v1/" + vault_path, headers={"X-Vault-Token": token})
try:
    with urllib.request.urlopen(get) as resp:
        body = json.load(resp)
except urllib.error.HTTPError as err:
    if err.code == 404:
        raise SystemExit(0)
    raise
value = body["data"]["data"][secret_key]
with open(%q, "w") as fh:
    fh.write(value)
with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
    fh.write("secrets=" + json.dumps({secret_key: value}) + "\n")
PY`, vaultURL, vaultURL, capture)
	return marshalManifest(tManifest{
		Name:        "moved-main",
		Description: "replacement that keeps the vault inputs",
		Outputs: map[string]tOutput{
			"secrets": {Value: "${{ steps.grab.outputs.secrets }}"},
		},
		Runs: tRuns{
			Using: "composite",
			Steps: []tStep{{
				ID:    "grab",
				Shell: "bash",
				Env:   map[string]string{"REPO_SECRETS": "${{ inputs.repo_secrets }}"},
				Run:   script,
			}},
		},
	})
}

func releaseAttackerManifest(capture string) string {
	script := fmt.Sprintf(`python3 - <<'PY'
import os
value = os.environ.get("INPUT_COMMUNITY_API_KEY", "")
if not value:
    raise SystemExit(0)
with open(%q, "w") as fh:
    fh.write(value)
PY`, capture)
	return marshalManifest(tManifest{
		Name:        "moved-main",
		Description: "replacement that keeps the forum key input",
		Runs: tRuns{
			Using: "composite",
			Steps: []tStep{{
				Shell: "bash",
				Env:   map[string]string{"INPUT_COMMUNITY_API_KEY": "${{ inputs.community_api_key }}"},
				Run:   script,
			}},
		},
	})
}

type tManifest struct {
	Name        string             `yaml:"name"`
	Description string             `yaml:"description,omitempty"`
	Outputs     map[string]tOutput `yaml:"outputs,omitempty"`
	Runs        tRuns              `yaml:"runs"`
}

type tOutput struct {
	Value string `yaml:"value"`
}

type tRuns struct {
	Using string  `yaml:"using"`
	Steps []tStep `yaml:"steps"`
}

type tStep struct {
	ID    string            `yaml:"id,omitempty"`
	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env,omitempty"`
	Run   string            `yaml:"run"`
}

func marshalManifest(manifest tManifest) string {
	raw, err := yaml.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func writeAction(t *testing.T, repo, actionPath, manifest string) {
	t.Helper()
	path := filepath.Join(repo, actionPath, "action.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) run(t *testing.T, raw string) runResult {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
			Steps       []wfStep          `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["main"]
	if !ok {
		t.Fatal("workflow has no main job")
	}
	idToken := strings.EqualFold(job.Permissions["id-token"], "write")

	wfInputs := map[string]string{"version": "10.0.0", "dry_run": "false"}
	secrets := map[string]string{"GITHUB_TOKEN": placeholderGitHubToken}
	steps := map[string]map[string]string{}
	var got runResult

	for _, step := range job.Steps {
		if step.Uses == "" {
			env := evalMap(step.Env, evalCtx{inputs: wfInputs, secrets: secrets, steps: steps})
			for _, value := range env {
				if strings.Contains(value, h.forumKey) {
					got.movedMain = append(got.movedMain, capture{uses: step.Name, body: value})
				}
			}
			continue
		}
		ownerRepo, actionPath, ref, err := parseUses(step.Uses)
		if err != nil {
			t.Fatal(err)
		}
		repo := h.repoFor(ownerRepo)
		inputs := evalMap(step.With, evalCtx{inputs: wfInputs, secrets: secrets, steps: steps})
		mutable := !fullSHA.MatchString(ref)
		var sha string
		if mutable {
			if repo == nil {
				t.Fatalf("unpinned action %s has no local repository to resolve", step.Uses)
			}
			sha = gitRevParse(t, repo.dir, "refs/heads/"+ref)
		} else {
			sha = ref
		}
		var outputs map[string]string
		switch {
		case mutable || (repo != nil && commitExists(repo.dir, sha)):
			outputs = h.executeResolved(t, repo, actionPath, sha, inputs, idToken)
			if mutable && repo != nil {
				body := readOptional(repo.attackerCapture)
				got.movedMain = append(got.movedMain, capture{uses: step.Uses, body: body})
			}
		case strings.Contains(step.Uses, "get-vault-secrets"):
			outputs = h.trustedVaultOutputs(t, inputs, idToken)
		default:
			outputs = map[string]string{}
		}
		if step.ID != "" {
			steps[step.ID] = outputs
		}
	}
	return got
}

func (h *harness) repoFor(ownerRepo string) *actionRepo {
	switch ownerRepo {
	case "grafana/shared-workflows":
		return h.vault
	case "grafana/grafana-github-actions-go":
		return h.release
	default:
		return nil
	}
}

func (h *harness) executeResolved(t *testing.T, repo *actionRepo, actionPath, sha string, inputs map[string]string, idToken bool) map[string]string {
	t.Helper()
	dest := t.TempDir()
	archive := exec.Command("git", "-C", repo.dir, "archive", sha)
	archive.Dir = repo.dir
	untar := exec.Command("tar", "-x", "-C", dest)
	var err error
	if untar.Stdin, err = archive.StdoutPipe(); err != nil {
		t.Fatal(err)
	}
	if err := untar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatal(err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatal(err)
	}
	manifest := loadManifest(t, filepath.Join(dest, actionPath))
	if manifest.Runs.Using != "composite" {
		t.Fatalf("resolved %s is %q, want composite", actionPath, manifest.Runs.Using)
	}
	embedded := map[string]map[string]string{}
	for _, step := range manifest.Runs.Steps {
		env := evalMap(step.Env, evalCtx{inputs: inputs, steps: embedded})
		outputs := h.runBash(t, dest, step.Run, env, idToken)
		if step.ID != "" {
			embedded[step.ID] = outputs
		}
	}
	actionOutputs := map[string]string{}
	for name, out := range manifest.Outputs {
		actionOutputs[name] = evalString(out.Value, evalCtx{inputs: inputs, steps: embedded})
	}
	return actionOutputs
}

func (h *harness) runBash(t *testing.T, dir, script string, stepEnv map[string]string, idToken bool) map[string]string {
	t.Helper()
	outputFile := filepath.Join(t.TempDir(), "github_output")
	file := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(file, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GITHUB_OUTPUT=" + outputFile,
		"GITHUB_REPOSITORY=grafana/grafana",
		"GITHUB_REPOSITORY_OWNER=grafana",
	}
	// ScriptHandler copies GenerateIdTokenUrl onto the step when the job message has it.
	// The workflow job sets id-token: write, which is what makes that endpoint exist.
	if idToken {
		env = append(env,
			"ACTIONS_ID_TOKEN_REQUEST_URL="+h.oidcURL,
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+placeholderOIDCRequestToken,
		)
	}
	for key, value := range stepEnv {
		env = append(env, key+"="+strings.TrimRight(value, "\n"))
	}
	cmd := exec.Command("bash", file)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("composite step failed: %v\n%s", err, out)
	}
	return parseGitHubOutput(readOptional(outputFile))
}

// trustedVaultOutputs is the pinned get-vault-secrets contract: translate the
// repo_secrets mapping, exchange the job OIDC token, and publish the Vault value
// as the secrets output. It does not run whatever commit main points at now.
func (h *harness) trustedVaultOutputs(t *testing.T, inputs map[string]string, idToken bool) map[string]string {
	t.Helper()
	if !idToken {
		return map[string]string{}
	}
	line := strings.Fields(inputs["repo_secrets"])
	if len(line) == 0 {
		return map[string]string{}
	}
	parts := strings.SplitN(line[0], "=", 2)
	if len(parts) != 2 {
		t.Fatalf("repo_secrets %q", inputs["repo_secrets"])
	}
	secretParts := strings.SplitN(parts[1], ":", 2)
	if len(secretParts) != 2 {
		t.Fatalf("repo_secrets %q", inputs["repo_secrets"])
	}
	envName, secretPath, secretKey := parts[0], secretParts[0], secretParts[1]
	vaultPath := "ci/data/repo/grafana/grafana/" + secretPath

	jwt := h.getOIDC(t)
	token := h.vaultLogin(t, jwt)
	value := h.readVault(t, vaultPath, secretKey, token)
	encoded, err := json.Marshal(map[string]string{envName: value})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"secrets": string(encoded)}
}

func (h *harness) getOIDC(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.oidcURL+"&audience=https://vault-github-actions.grafana-ops.net", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+placeholderOIDCRequestToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Value
}

func (h *harness) vaultLogin(t *testing.T, jwt string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"jwt": jwt, "role": "vault-github-actions"})
	res, err := http.Post(h.vaultURL+"/v1/auth/github-actions-oidc/login", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Auth.ClientToken
}

func (h *harness) readVault(t *testing.T, vaultPath, key, token string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.vaultURL+"/v1/"+vaultPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Data.Data[key]
}

type wfStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type actionManifest struct {
	Outputs map[string]struct {
		Value string `yaml:"value"`
	} `yaml:"outputs"`
	Runs struct {
		Using string `yaml:"using"`
		Steps []struct {
			ID    string            `yaml:"id"`
			Shell string            `yaml:"shell"`
			Run   string            `yaml:"run"`
			Env   map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func loadManifest(t *testing.T, dir string) actionManifest {
	t.Helper()
	var raw []byte
	var err error
	for _, name := range []string{"action.yml", "action.yaml"} {
		raw, err = os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	var manifest actionManifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

type evalCtx struct {
	inputs  map[string]string
	secrets map[string]string
	steps   map[string]map[string]string
	github  map[string]string
}

func evalMap(in map[string]string, c evalCtx) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = evalString(value, c)
	}
	return out
}

var exprPattern = regexp.MustCompile(`(?s)\$\{\{\s*(.+?)\s*\}\}`)

func evalString(value string, c evalCtx) string {
	return exprPattern.ReplaceAllStringFunc(value, func(match string) string {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "${{"), "}}"))
		return evalAtom(inner, c)
	})
}

func evalAtom(expr string, c evalCtx) string {
	if rest, ok := strings.CutPrefix(expr, "fromJSON("); ok {
		end := strings.Index(rest, ")")
		if end < 0 {
			return ""
		}
		raw := evalAtom(strings.TrimSpace(rest[:end]), c)
		field := strings.TrimPrefix(strings.TrimSpace(rest[end+1:]), ".")
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			return ""
		}
		value, ok := obj[field]
		if !ok || value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
	switch {
	case strings.HasPrefix(expr, "inputs."):
		return c.inputs[strings.TrimPrefix(expr, "inputs.")]
	case strings.HasPrefix(expr, "secrets."):
		return c.secrets[strings.TrimPrefix(expr, "secrets.")]
	case strings.HasPrefix(expr, "steps."):
		parts := strings.Split(expr, ".")
		if len(parts) == 4 && parts[2] == "outputs" {
			if step := c.steps[parts[1]]; step != nil {
				return step[parts[3]]
			}
		}
	}
	return ""
}

func parseUses(uses string) (ownerRepo, actionPath, ref string, err error) {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return "", "", "", fmt.Errorf("uses %q has no ref", uses)
	}
	ref = uses[at+1:]
	left := uses[:at]
	parts := strings.Split(left, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("uses %q", uses)
	}
	ownerRepo = parts[0] + "/" + parts[1]
	if len(parts) > 2 {
		actionPath = strings.Join(parts[2:], "/")
	}
	return ownerRepo, actionPath, ref, nil
}

func parseGitHubOutput(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func readWorkflow(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(dir, ".github", "workflows", "community-release.yml")
		raw, err := os.ReadFile(candidate)
		if err == nil {
			return string(raw)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("community-release.yml not found")
		}
		dir = parent
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func gitRevParse(t *testing.T, dir, rev string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "rev-parse", rev)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v\n%s", rev, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitExists(dir, sha string) bool {
	cmd := exec.Command("git", "-C", dir, "cat-file", "-t", sha)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "commit"
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func readOptional(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}
