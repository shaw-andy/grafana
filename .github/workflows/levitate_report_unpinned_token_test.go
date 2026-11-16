package workflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	workflowFile = "detect-breaking-changes-levitate.yml"

	// Obvious placeholders. The test never uses a real credential.
	installationToken = "installation-token-placeholder"
	jobToken          = "job-token-placeholder"
	idTokenRequest    = "id-token-request-placeholder"
	idTokenURL        = "https://example.invalid/actions-id-token"

	appTokenExpr = "steps.get-github-app-token.outputs.token"
)

// TestLevitateReportUnpinnedGitHubScriptDoesNotReceiveCredentials follows the
// Report job in detect-breaking-changes-levitate.yml. It mints the
// grafana-pr-automation installation token the way create_token.sh publishes
// it, wires that output into each step, and runs the action entrypoint the
// runner would run after resolving uses:.
//
// A full 40-character commit SHA stays on the action that was pinned. Any
// other ref is republished before the job runs. The republished entrypoint
// records the credential values the runner places in the action process.
func TestLevitateReportUnpinnedGitHubScriptDoesNotReceiveCredentials(t *testing.T) {
	workflowPath := filepath.Join(workflowFile)
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	wf, err := parseWorkflow(raw)
	if err != nil {
		t.Fatalf("parse workflow: %v", err)
	}

	rawUses := strings.Count(string(raw), "actions/github-script@")
	if rawUses != len(wf.reportScriptSteps()) {
		t.Fatalf("parsed %d actions/github-script steps, file contains %d uses", len(wf.reportScriptSteps()), rawUses)
	}

	changed := "packages/grafana-data/package.json"
	if !wf.triggersOn(changed) {
		t.Fatalf("path filter did not select %s; the package pull-request path is part of the job", changed)
	}

	sameRepo := map[string]string{
		"github.repository":                             "grafana/grafana",
		"github.event.pull_request.head.repo.full_name": "grafana/grafana",
		"github.event.pull_request.number":              "135226",
		"github.token":                                  jobToken,
	}
	runs, err := wf.reportRuns(sameRepo)
	if err != nil {
		t.Fatalf("same-repository pull request: %v", err)
	}
	if !runs {
		t.Fatal("same-repository pull request did not run the Report job")
	}

	fork := map[string]string{
		"github.repository":                             "grafana/grafana",
		"github.event.pull_request.head.repo.full_name": "attacker/grafana",
	}
	forkRuns, err := wf.reportRuns(fork)
	if err != nil {
		t.Fatalf("fork pull request: %v", err)
	}
	if forkRuns {
		t.Fatal("fork pull request ran the Report job")
	}

	token, err := mintInstallationToken(t, installationToken)
	if err != nil {
		t.Fatalf("mint installation token: %v", err)
	}
	if token != installationToken {
		t.Fatalf("installation token output = %q", token)
	}

	root := t.TempDir()
	legitimate := writeAction(t, root, "legitimate", legitimateMainJS)
	attacker := writeAction(t, root, "attacker", attackerMainJS)

	scenarios := []map[string]string{
		{"steps.levitate-run.outputs.exit_code": "1", "steps.does-label-exist.outputs.result": "0", "steps.levitate-run.outputs.pr_number": "135226"},
		{"steps.levitate-run.outputs.exit_code": "0", "steps.does-label-exist.outputs.result": "1", "steps.levitate-run.outputs.pr_number": "135226"},
	}
	executed := map[string]bool{}
	for _, extra := range scenarios {
		ctx := cloneMap(sameRepo)
		for k, v := range extra {
			ctx[k] = v
		}
		ctx[appTokenExpr] = token
		for _, step := range wf.Report.Steps {
			if step.Uses == "" || !strings.HasPrefix(step.Uses, "actions/github-script@") {
				continue
			}
			run, err := step.runs(ctx)
			if err != nil {
				t.Fatalf("step %q if: %v", step.display(), err)
			}
			if !run {
				continue
			}
			executed[step.display()] = true
			observed := runResolvedAction(t, step, ctx, wf.Report.oidcEnabled(), legitimate, attacker)
			if observed.GitHubToken == installationToken {
				t.Errorf("step %q (%s) ran the republished actions/github-script entrypoint with the grafana-pr-automation installation token", step.display(), step.Uses)
			}
			if wf.Report.oidcEnabled() && (observed.IDTokenRequestToken == idTokenRequest || observed.IDTokenURL == idTokenURL) {
				t.Errorf("step %q (%s) ran the republished actions/github-script entrypoint with the job OIDC request credentials", step.display(), step.Uses)
			}
		}
	}

	for _, marker := range []string{"issues.addLabels", "issues.removeLabel", "pulls.requestReviewers", "pulls.removeRequestedReviewers"} {
		found := false
		ran := false
		for _, step := range wf.reportScriptSteps() {
			if strings.Contains(step.script(), marker) {
				found = true
				if executed[step.display()] {
					ran = true
				}
			}
		}
		if found && !ran {
			t.Errorf("operation %s is in the Report job but no scenario ran it", marker)
		}
	}
}

// mintInstallationToken runs the token extraction and GITHUB_OUTPUT write from
// create_token.sh at grafana/shared-workflows 46f48da11e78ebdba7a8747ae456b11062fac83e,
// then applies the composite output name from that action's action.yaml.
func mintInstallationToken(t *testing.T, placeholder string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	body := filepath.Join(dir, "vault.json")
	// The sed below is the parser create_token.sh uses. The body only has to
	// contain a JSON "token" string; the script does not decode JSON.
	payload := `{"data":{"token":"` + placeholder + `"}}`
	if err := os.WriteFile(body, []byte(payload), 0o600); err != nil {
		return "", err
	}
	output := filepath.Join(dir, "github_output")
	script := `
set -euo pipefail
TEMP_FILE="$1"
GITHUB_OUTPUT="$2"
TOKEN=$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${TEMP_FILE}" | head -n1)
if [[ -z "${TOKEN}" ]]; then
  echo "Failed to parse token from Vault response" >&2
  exit 1
fi
echo "github_token=${TOKEN}" >> "${GITHUB_OUTPUT}"
`
	cmd := exec.Command("bash", "-c", script, "bash", body, output)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	pairs, err := parseGitHubOutput(output)
	if err != nil {
		return "", err
	}
	// action.yaml outputs.token = steps.generate-token.outputs.github_token
	return pairs["github_token"], nil
}

type observedCredentials struct {
	GitHubToken         string `json:"githubToken"`
	IDTokenRequestToken string `json:"idTokenRequestToken"`
	IDTokenURL          string `json:"idTokenURL"`
	Entrypoint          string `json:"entrypoint"`
}

func runResolvedAction(t *testing.T, step step, ctx map[string]string, oidc bool, legitimate, attacker string) observedCredentials {
	t.Helper()
	ref := refOf(step.Uses)
	dir := legitimate
	if !fullCommitSHA(ref) {
		// The tag or branch is resolved when the job runs. Republishing it
		// selects the new entrypoint. A full commit SHA does not follow that move.
		dir = attacker
	}
	manifest, err := readActionManifest(filepath.Join(dir, "action.yml"))
	if err != nil {
		t.Fatalf("action manifest: %v", err)
	}
	inputs := map[string]string{}
	for k, v := range step.With {
		inputs[strings.ToLower(k)] = evalExprs(v, ctx)
	}
	for k, def := range manifest.defaults {
		if _, ok := inputs[k]; !ok {
			inputs[k] = evalExprs(def, ctx)
		}
	}
	env := addInputsToEnvironment(inputs)
	if oidc {
		// NodeScriptActionHandler copies these into every node action when the
		// job connection has GenerateIdTokenUrl, which id-token: write causes.
		env["ACTIONS_ID_TOKEN_REQUEST_URL"] = idTokenURL
		env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = idTokenRequest
	}
	sink := filepath.Join(t.TempDir(), "sink.json")
	env["SINK"] = sink
	env["PATH"] = os.Getenv("PATH")
	main := filepath.Join(dir, manifest.main)
	cmd := exec.Command("node", main)
	cmd.Env = envList(env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s main: %v\n%s", step.Uses, err, out)
	}
	body, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	var got observedCredentials
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("sink json: %v (%s)", err, body)
	}
	return got
}

// addInputsToEnvironment is Handler.AddInputsToEnvironment: INPUT_ plus the
// uppercased name, with spaces replaced by underscores. Hyphens stay, so
// github-token becomes INPUT_GITHUB-TOKEN. @actions/core getInput reads that
// same name.
func addInputsToEnvironment(inputs map[string]string) map[string]string {
	env := make(map[string]string, len(inputs))
	for key, value := range inputs {
		env["INPUT_"+strings.ToUpper(strings.ReplaceAll(key, " ", "_"))] = value
	}
	return env
}

func envList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

type actionManifest struct {
	main     string
	defaults map[string]string
}

func readActionManifest(path string) (actionManifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return actionManifest{}, err
	}
	var raw struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Runs struct {
			Main string `yaml:"main"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return actionManifest{}, err
	}
	if raw.Runs.Main == "" {
		return actionManifest{}, fmt.Errorf("runs.main missing")
	}
	m := actionManifest{main: raw.Runs.Main, defaults: map[string]string{}}
	for name, input := range raw.Inputs {
		if input.Default != "" {
			m.defaults[strings.ToLower(name)] = input.Default
		}
	}
	return m, nil
}

func writeAction(t *testing.T, root, name, mainJS string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: stand-in\ninputs:\n  github-token:\n    default: ${{ github.token }}\nruns:\n  using: node24\n  main: main.js\n")
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte(mainJS), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// legitimateMainJS is the credential path in actions/github-script v8
// (src/main.ts getInput('github-token') then getOctokit) using @actions/core
// 1.10.1 getInput and @actions/github 6.0.0 getAuthString. It does not record
// the token. A pinned SHA stays on this entrypoint.
const legitimateMainJS = `
const fs = require('fs');
function getInput(name) {
  const val = process.env['INPUT_' + name.replace(/ /g, '_').toUpperCase()] || '';
  return val.trim();
}
function getAuthString(token, options) {
  const opts = options || {};
  if (!token && !opts.auth) {
    throw new Error('Parameter token or opts.auth is required');
  }
  if (token && opts.auth) {
    throw new Error('Parameters token and opts.auth may not both be specified');
  }
  return typeof opts.auth === 'string' ? opts.auth : 'token ' + token;
}
const token = getInput('github-token');
if (!token) {
  throw new Error('Input required and not supplied: github-token');
}
const auth = getAuthString(token, {});
if (!auth.startsWith('token ')) {
  throw new Error('auth scheme was not formed');
}
fs.writeFileSync(process.env.SINK, JSON.stringify({
  githubToken: '',
  idTokenRequestToken: '',
  idTokenURL: '',
  entrypoint: 'legitimate'
}));
`

// attackerMainJS is the entrypoint published over the mutable ref. The runner
// has already copied inputs and the OIDC request into the process environment
// before executing runs.main.
const attackerMainJS = `
const fs = require('fs');
fs.writeFileSync(process.env.SINK, JSON.stringify({
  githubToken: process.env['INPUT_GITHUB-TOKEN'] || '',
  idTokenRequestToken: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '',
  idTokenURL: process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '',
  entrypoint: 'republished'
}));
`

func parseGitHubOutput(path string) (map[string]string, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pairs := map[string]string{}
	for _, line := range bytes.Split(text, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		eq := bytes.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("invalid GITHUB_OUTPUT line %q", line)
		}
		pairs[string(line[:eq])] = string(line[eq+1:])
	}
	return pairs, nil
}

type workflow struct {
	paths  []string
	Report job
}

type job struct {
	If          string
	Permissions map[string]string
	Steps       []step
}

func (j job) oidcEnabled() bool {
	return strings.EqualFold(j.Permissions["id-token"], "write")
}

type step struct {
	Name string
	ID   string
	Uses string
	If   string
	With map[string]string
}

func (s step) display() string {
	if s.Name != "" {
		return s.Name
	}
	if s.ID != "" {
		return s.ID
	}
	return s.Uses
}

func (s step) script() string {
	return s.With["script"]
}

func (w workflow) reportScriptSteps() []step {
	var out []step
	for _, s := range w.Report.Steps {
		if strings.HasPrefix(s.Uses, "actions/github-script@") {
			out = append(out, s)
		}
	}
	return out
}

func (w workflow) triggersOn(path string) bool {
	if len(w.paths) == 0 {
		return true
	}
	for _, pattern := range w.paths {
		if matchFilter(pattern, path) {
			return true
		}
	}
	return false
}

func (w workflow) reportRuns(ctx map[string]string) (bool, error) {
	if strings.TrimSpace(w.Report.If) == "" {
		return true, nil
	}
	return evalBool(w.Report.If, ctx)
}

func (s step) runs(ctx map[string]string) (bool, error) {
	if strings.TrimSpace(s.If) == "" {
		return true, nil
	}
	return evalBool(s.If, ctx)
}

func parseWorkflow(raw []byte) (workflow, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return workflow{}, err
	}
	on, _ := doc["on"].(map[string]any)
	pr, _ := on["pull_request"].(map[string]any)
	var paths []string
	if rawPaths, ok := pr["paths"].([]any); ok {
		for _, p := range rawPaths {
			paths = append(paths, fmt.Sprint(p))
		}
	}
	jobs, _ := doc["jobs"].(map[string]any)
	reportRaw, _ := jobs["Report"].(map[string]any)
	if reportRaw == nil {
		return workflow{}, fmt.Errorf("Report job missing")
	}
	report := job{Permissions: map[string]string{}, If: fmt.Sprint(reportRaw["if"])}
	if report.If == "<nil>" {
		report.If = ""
	}
	if perms, ok := reportRaw["permissions"].(map[string]any); ok {
		for k, v := range perms {
			report.Permissions[fmt.Sprint(k)] = fmt.Sprint(v)
		}
	}
	steps, _ := reportRaw["steps"].([]any)
	for _, rawStep := range steps {
		sm, _ := rawStep.(map[string]any)
		st := step{
			Name: stringField(sm, "name"),
			ID:   stringField(sm, "id"),
			Uses: stringField(sm, "uses"),
			If:   stringField(sm, "if"),
			With: map[string]string{},
		}
		if with, ok := sm["with"].(map[string]any); ok {
			for k, v := range with {
				st.With[fmt.Sprint(k)] = fmt.Sprint(v)
			}
		}
		report.Steps = append(report.Steps, st)
	}
	return workflow{paths: paths, Report: report}, nil
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func matchFilter(pattern, path string) bool {
	pattern = strings.TrimPrefix(pattern, "/")
	path = strings.TrimPrefix(path, "/")
	re := regexp.MustCompile("^" + globToRegexp(pattern) + "$")
	return re.MatchString(path)
}

func globToRegexp(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
				}
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	return b.String()
}

var exprPattern = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

func evalExprs(s string, ctx map[string]string) string {
	return exprPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := exprPattern.FindStringSubmatch(match)
		value, ok := lookup(strings.TrimSpace(parts[1]), ctx)
		if !ok {
			return match
		}
		return value
	})
}

func evalBool(expr string, ctx map[string]string) (bool, error) {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimPrefix(expr, "${{")
	expr = strings.TrimSuffix(expr, "}}")
	expr = strings.TrimSpace(expr)
	parts := strings.Split(expr, "&&")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lhs, rhs, ok := strings.Cut(part, "==")
		if !ok {
			return false, fmt.Errorf("unsupported expression %q", expr)
		}
		lv, lok := lookup(strings.TrimSpace(lhs), ctx)
		rv, rok := lookup(strings.TrimSpace(rhs), ctx)
		if !lok || !rok {
			return false, fmt.Errorf("unresolved comparison %q", part)
		}
		if lv != rv {
			return false, nil
		}
	}
	return true, nil
}

func lookup(token string, ctx map[string]string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	if strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'") && len(token) >= 2 {
		return token[1 : len(token)-1], true
	}
	if strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`) && len(token) >= 2 {
		return token[1 : len(token)-1], true
	}
	if v, ok := ctx[token]; ok {
		return v, true
	}
	if isNumber(token) {
		return token, true
	}
	if !strings.Contains(token, ".") && !strings.Contains(token, "-") {
		return token, true
	}
	return "", false
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func refOf(uses string) string {
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		return uses[i+1:]
	}
	return ""
}

func fullCommitSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
