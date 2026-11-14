package crowdinworkflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// placeholderCrowdinToken is the value a KV v2 read would return for
// grafana-frontend-crowdin-token's access_token key. It is not a credential.
const placeholderCrowdinToken = "placeholder-crowdin-access-token"

// placeholderVaultBody is the KV v2 response shape selectAndAppendResults reads
// (body.data.data) for that key.
const placeholderVaultBody = `{"data":{"data":{"access_token":"` + placeholderCrowdinToken + `"},"metadata":{}}}`

const pinnedSHA = "0123456789abcdef0123456789abcdef01234567"

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestCrowdinTokenIsNotDeliveredToAMovingActionRef runs the Crowdin workflows
// the way the runner at actions/runner v2.338.2 runs them: a uses ref is
// resolved when the job starts, composite inputs are copied into the
// expression context, and step env expressions are evaluated before the
// process starts. The branch tip is moved after an earlier resolution. The
// job must execute that later tip. The token may be observed only by an
// action pinned to a full commit SHA.
func TestCrowdinTokenIsNotDeliveredToAMovingActionRef(t *testing.T) {
	repo, tip := actionRepo(t)
	for _, file := range crowdinWorkflows(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			assertTokenStaysOnFullSHAs(t, file, body, repo, tip)
		})
	}
}

// TestPinnedCrowdinActionsKeepTheTokenAwayFromTheBranchTip is the same run
// after every @main use is replaced with a full commit SHA. The branch tip
// still moves, and the token still has to reach the upload step.
func TestPinnedCrowdinActionsKeepTheTokenAwayFromTheBranchTip(t *testing.T) {
	repo, tip := actionRepo(t)
	for _, file := range crowdinWorkflows(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			pinned := bytes.ReplaceAll(body, []byte("@main"), []byte("@"+pinnedSHA))
			assertTokenStaysOnFullSHAs(t, file, pinned, repo, tip)
		})
	}
}

func assertTokenStaysOnFullSHAs(t *testing.T, file string, body []byte, actionRepo, attackerTip string) {
	t.Helper()
	wf, err := parseWorkflow(body)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	if !workflowCanRun(wf) {
		t.Fatalf("%s no longer has a push, schedule, or workflow_dispatch trigger", file)
	}

	bin := testBin(t)
	var observers []observer
	for name, job := range wf.Jobs {
		if !jobSelected(job.If, "grafana/grafana") {
			continue
		}
		idToken := job.Permissions["id-token"] == "write"
		steps := map[string]map[string]string{}
		for i, step := range job.Steps {
			if isCrowdinVaultStep(step) {
				if !idToken {
					t.Fatalf("%s job %s reads the crowdin vault secret without id-token: write", file, name)
				}
				token := selectCrowdinToken(t, bin, step.With["repo_secrets"], "grafana/grafana")
				ref := mustRef(t, step.Uses)
				if !fullSHA.MatchString(ref) {
					resolved := resolveAtJobStart(t, actionRepo, ref)
					if resolved != attackerTip {
						t.Fatalf("%s resolved %s to %s, attacker tip is %s", file, ref, resolved, attackerTip)
					}
					captured := runMovedAction(t, bin, actionRepo, resolved, idToken, map[string]string{
						"repo_secrets": step.With["repo_secrets"],
					})
					if !strings.Contains(captured, token) {
						t.Fatalf("%s vault step ref %s did not observe the crowdin token at the moved tip", file, ref)
					}
				}
				outputs := map[string]string{"CROWDIN_TOKEN": token}
				if step.ID == "" {
					t.Fatalf("%s vault step has no id", file)
				}
				raw, err := json.Marshal(outputs)
				if err != nil {
					t.Fatal(err)
				}
				steps[step.ID] = map[string]string{"secrets": string(raw)}
				observers = append(observers, observer{step: label(i, step), ref: ref})
				continue
			}

			inputs := evalMap(step.With, steps)
			env := evalMap(step.Env, steps)
			run := evalString(step.Run, steps, nil)
			if !observesToken(inputs, env, run) {
				continue
			}
			if step.Uses == "" {
				t.Errorf("%s step %s is an inline run that receives the crowdin token", file, label(i, step))
				continue
			}
			ref := mustRef(t, step.Uses)
			if !fullSHA.MatchString(ref) {
				resolved := resolveAtJobStart(t, actionRepo, ref)
				if resolved != attackerTip {
					t.Fatalf("%s resolved %s to %s, attacker tip is %s", file, ref, resolved, attackerTip)
				}
				captured := runMovedAction(t, bin, actionRepo, resolved, idToken, inputs)
				if !strings.Contains(captured, placeholderCrowdinToken) {
					t.Fatalf("%s step %s ref %s evaluated the token into the action but the moved action did not observe it", file, label(i, step), ref)
				}
			}
			observers = append(observers, observer{step: label(i, step), ref: ref})
		}
		if len(observers) == 0 {
			t.Fatalf("%s job %s did not deliver the crowdin token to any step", file, name)
		}
		for _, ob := range observers {
			if !fullSHA.MatchString(ob.ref) {
				t.Errorf("%s step %s uses %s, which is not a full commit SHA, and that action observed the crowdin token", file, ob.step, ob.ref)
			}
		}
	}
}

type observer struct {
	step string
	ref  string
}

func label(i int, step step) string {
	if step.Name != "" {
		return step.Name
	}
	if step.ID != "" {
		return step.ID
	}
	return fmt.Sprintf("#%d", i)
}

type workflowFile struct {
	Jobs map[string]job `yaml:"jobs"`
	On   yaml.Node      `yaml:"on"`
}

type job struct {
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []step            `yaml:"steps"`
}

type step struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type actionFile struct {
	Outputs map[string]struct {
		Value string `yaml:"value"`
	} `yaml:"outputs"`
	Runs struct {
		Using string       `yaml:"using"`
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

type actionStep struct {
	ID    string            `yaml:"id"`
	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env"`
	Run   string            `yaml:"run"`
}

func parseWorkflow(body []byte) (workflowFile, error) {
	var wf workflowFile
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(false)
	err := dec.Decode(&wf)
	return wf, err
}

func workflowCanRun(wf workflowFile) bool {
	for _, key := range mappingKeys(wf.On) {
		switch key {
		case "workflow_dispatch", "schedule", "push":
			return true
		}
	}
	return false
}

func mappingKeys(node yaml.Node) []string {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var keys []string
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}

func jobSelected(ifExpr, repository string) bool {
	expr := strings.TrimSpace(ifExpr)
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "${{"), "}}"))
	if expr == "" {
		return true
	}
	for _, part := range strings.Split(expr, "&&") {
		part = strings.TrimSpace(part)
		if !equalityHolds(part, repository) {
			return false
		}
	}
	return true
}

func equalityHolds(expr, repository string) bool {
	sides := strings.Split(expr, "==")
	if len(sides) != 2 {
		return false
	}
	left := strings.TrimSpace(sides[0])
	right := strings.Trim(strings.TrimSpace(sides[1]), `"'`)
	if left == "github.repository" {
		return right == repository
	}
	return false
}

func isCrowdinVaultStep(step step) bool {
	return strings.Contains(step.Uses, "get-vault-secrets") || strings.Contains(step.With["repo_secrets"], "grafana-frontend-crowdin-token")
}

func observesToken(inputs, env map[string]string, run string) bool {
	for _, value := range inputs {
		if strings.Contains(value, placeholderCrowdinToken) {
			return true
		}
	}
	for _, value := range env {
		if strings.Contains(value, placeholderCrowdinToken) {
			return true
		}
	}
	return strings.Contains(run, placeholderCrowdinToken)
}

func mustRef(t *testing.T, uses string) string {
	t.Helper()
	_, ref, ok := splitUses(uses)
	if !ok {
		t.Fatalf("uses %q has no ref", uses)
	}
	return ref
}

func splitUses(uses string) (name, ref string, ok bool) {
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return "", "", false
	}
	return uses[:at], uses[at+1:], true
}

func evalMap(values map[string]string, steps map[string]map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = evalString(value, steps, nil)
	}
	return out
}

func evalString(value string, steps map[string]map[string]string, inputs map[string]string) string {
	var b strings.Builder
	rest := value
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
			b.WriteString("${{")
			b.WriteString(rest)
			break
		}
		b.WriteString(evalExpr(strings.TrimSpace(rest[:end]), steps, inputs))
		rest = rest[end+2:]
	}
	return b.String()
}

func evalExpr(expr string, steps map[string]map[string]string, inputs map[string]string) string {
	if strings.HasPrefix(expr, "fromJSON(") {
		open := strings.Index(expr, "(")
		close := strings.Index(expr, ")")
		if open < 0 || close < open {
			return ""
		}
		raw := evalExpr(strings.TrimSpace(expr[open+1:close]), steps, inputs)
		var object map[string]any
		if err := json.Unmarshal([]byte(raw), &object); err != nil {
			return ""
		}
		field := strings.TrimPrefix(expr[close+1:], ".")
		value, ok := object[field]
		if !ok {
			return ""
		}
		return fmt.Sprint(value)
	}
	if strings.HasPrefix(expr, "toJSON(") && strings.HasSuffix(expr, ")") {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "toJSON("), ")"))
		if !strings.HasPrefix(inner, "steps.") || !strings.HasSuffix(inner, ".outputs") {
			return ""
		}
		id := strings.TrimSuffix(strings.TrimPrefix(inner, "steps."), ".outputs")
		raw, err := json.Marshal(steps[id])
		if err != nil {
			return ""
		}
		return string(raw)
	}
	if strings.HasPrefix(expr, "inputs.") {
		return inputs[strings.TrimPrefix(expr, "inputs.")]
	}
	if expr == "github.repository" {
		return "grafana/grafana"
	}
	if strings.HasPrefix(expr, "steps.") {
		rest := strings.TrimPrefix(expr, "steps.")
		id, output, ok := strings.Cut(rest, ".outputs.")
		if !ok {
			return ""
		}
		return steps[id][output]
	}
	return ""
}

func crowdinWorkflows(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, match := range matches {
		body, err := os.ReadFile(match)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("grafana-frontend-crowdin-token")) {
			files = append(files, match)
		}
	}
	required := []string{
		"i18n-crowdin-upload.yml",
		"i18n-crowdin-download.yml",
		"i18n-crowdin-create-tasks.yml",
	}
	for _, name := range required {
		found := false
		for _, file := range files {
			if filepath.Base(file) == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %s", name)
		}
	}
	return files
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
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

func testdata(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata")
}

type binPaths struct {
	dir     string
	jsonata string
}

func testBin(t *testing.T) binPaths {
	t.Helper()
	dir := t.TempDir()
	data := testdata(t)
	selectSrc := filepath.Join(data, "vault-select")
	selectDst := filepath.Join(dir, "vault-select")
	body, err := os.ReadFile(selectSrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selectDst, body, 0o755); err != nil {
		t.Fatal(err)
	}
	// testdata/jsonata.js is the jsonata 2.0.4 build locked by vault-action@892a268.
	return binPaths{dir: dir, jsonata: filepath.Join(data, "jsonata.js")}
}

func selectCrowdinToken(t *testing.T, bin binPaths, repoSecrets, repository string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(bin.dir, "vault-select"), repoSecrets, repository)
	cmd.Env = vaultEnv(t, bin, true)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vault-select: %v\n%s", err, out)
	}
	values := parseEqualsOutput(string(out))
	if values["CROWDIN_TOKEN"] != placeholderCrowdinToken {
		t.Fatalf("vault-select did not return the crowdin token output, got keys %v", mapsKeys(values))
	}
	return values["CROWDIN_TOKEN"]
}

func mapsKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func vaultEnv(t *testing.T, bin binPaths, idToken bool) []string {
	t.Helper()
	data := testdata(t)
	env := []string{
		"PATH=" + bin.dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TRANSLATE_SECRETS=" + filepath.Join(data, "translate-secrets.bash"),
		"VAULT_DRIVER=" + filepath.Join(data, "vault-driver.js"),
		"GET_ID_TOKEN=" + filepath.Join(data, "get-id-token.js"),
		"JSONATA_MODULE=" + bin.jsonata,
		"VAULT_BODY=" + placeholderVaultBody,
		"VAULT_INSTANCE=ops",
		"VERSION=v1",
	}
	if idToken {
		// ScriptHandler sets these when the job endpoint carries GenerateIdTokenUrl.
		env = append(env,
			"ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.example/token?stub=1",
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN=placeholder-request-token",
		)
	}
	return env
}

func parseEqualsOutput(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		values[key] = value
	}
	return values
}

// actionRepo builds the action repository the workflows reference with @main.
// The first commit is the reviewed tree. main is then moved to a second commit
// that records every input and vault output it was given.
func actionRepo(t *testing.T) (dir, tip string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-b", "main")
	writeAction(t, dir, benignAction)
	git(t, dir, "add", "action.yml")
	git(t, dir, "commit", "-m", "reviewed action")
	benign := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	writeAction(t, dir, attackerAction)
	git(t, dir, "add", "action.yml")
	git(t, dir, "commit", "-m", "moved main")
	tip = strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	if benign == tip {
		t.Fatal("main did not move")
	}
	if strings.TrimSpace(git(t, dir, "rev-parse", benign)) != benign {
		t.Fatal("reviewed commit is no longer reachable")
	}
	return dir, tip
}

func resolveAtJobStart(t *testing.T, repo, ref string) string {
	t.Helper()
	if fullSHA.MatchString(ref) {
		return ref
	}
	return strings.TrimSpace(git(t, repo, "rev-parse", "refs/heads/"+ref))
}

func writeAction(t *testing.T, repo, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, "action.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Crowdin Token Test",
		"GIT_AUTHOR_EMAIL=crowdin-token-test@example.com",
		"GIT_COMMITTER_NAME=Crowdin Token Test",
		"GIT_COMMITTER_EMAIL=crowdin-token-test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func runMovedAction(t *testing.T, bin binPaths, repo, sha string, idToken bool, inputs map[string]string) string {
	t.Helper()
	raw := git(t, repo, "show", sha+":action.yml")
	var action actionFile
	if err := yaml.Unmarshal([]byte(raw), &action); err != nil {
		t.Fatal(err)
	}
	if action.Runs.Using != "composite" {
		t.Fatalf("moved action using=%s", action.Runs.Using)
	}
	capture := filepath.Join(t.TempDir(), "capture")
	if err := os.WriteFile(capture, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	actionSteps := map[string]map[string]string{}
	failed := false
	for _, step := range action.Runs.Steps {
		if failed {
			break
		}
		outputFile := filepath.Join(t.TempDir(), "github-output")
		if err := os.WriteFile(outputFile, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		env := vaultEnv(t, bin, idToken)
		env = append(env, "GITHUB_OUTPUT="+outputFile, "CAPTURE="+capture)
		for key, value := range step.Env {
			env = append(env, key+"="+evalString(value, actionSteps, inputs))
		}
		script := filepath.Join(t.TempDir(), "step.sh")
		if err := os.WriteFile(script, []byte(step.Run), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", script)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			failed = true
			t.Logf("moved action step failed: %v\n%s", err, out)
		}
		if step.ID != "" {
			actionSteps[step.ID] = parseEqualsOutput(readFile(t, outputFile))
		}
	}
	for _, output := range action.Outputs {
		evalString(output.Value, actionSteps, inputs)
	}
	return readFile(t, capture)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

const benignAction = `name: reviewed
runs:
  using: composite
  steps:
    - shell: bash
      run: echo reviewed
`

const attackerAction = `name: moved
description: records the crowdin token handed to this action
inputs:
  crowdin_token:
    required: false
  repo_secrets:
    required: false
outputs:
  secrets:
    value: ${{ toJSON(steps.import-secrets.outputs) }}
runs:
  using: composite
  steps:
    - id: import-secrets
      shell: bash
      env:
        REPO_SECRETS: ${{ inputs.repo_secrets }}
        REPO: ${{ github.repository }}
      run: |
        if [ -n "$REPO_SECRETS" ]; then
          vault-select "$REPO_SECRETS" "$REPO" >> "$GITHUB_OUTPUT"
        fi
    - shell: bash
      env:
        CROWDIN_TOKEN_INPUT: ${{ inputs.crowdin_token }}
        CROWDIN_TOKEN_OUTPUT: ${{ steps.import-secrets.outputs.CROWDIN_TOKEN }}
      run: |
        printf 'input=%s\noutput=%s\n' "$CROWDIN_TOKEN_INPUT" "$CROWDIN_TOKEN_OUTPUT" >> "$CAPTURE"
`
