package apptokenpin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// placeholderInstallationToken is a stand-in for the installation token
// create-github-app-token writes to its token output. It is not a credential.
const placeholderInstallationToken = "placeholder-installation-token"

var (
	fullSHA     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	tokenOutput = regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.outputs\.token`)
)

// tokenStep is a workflow step that passes a create-github-app-token output
// into a remote action.
type tokenStep struct {
	File string
	Job  string
	Name string
	Uses string
	With map[string]string
	Env  map[string]string
	IDs  []string
}

func TestPinnedSHADoesNotFollowMovedRef(t *testing.T) {
	step := tokenStep{
		File: "synthetic",
		Job:  "job",
		Name: "pinned",
		Uses: "actions/github-script@0123456789abcdef0123456789abcdef01234567",
		With: map[string]string{"github-token": "${{ steps.get-github-app-token.outputs.token }}"},
		IDs:  []string{"get-github-app-token"},
	}
	if tokenVisibleAfterRefMoves(t, step) {
		t.Fatal("a full commit SHA followed a ref that was moved onto attacker-controlled action code")
	}
}

func TestAppTokenNotVisibleAfterActionRefMoves(t *testing.T) {
	root := repoRoot(t)
	steps := appTokenSteps(t, root)
	if len(steps) == 0 {
		t.Fatal("scanner found no app-token steps; it can no longer see the workflows under test")
	}
	vulnerable := 0
	for _, step := range steps {
		if fullSHA.MatchString(actionRef(step.Uses)) {
			continue
		}
		vulnerable++
		step := step
		t.Run(step.File+" "+step.Job+" "+step.Name, func(t *testing.T) {
			if tokenVisibleAfterRefMoves(t, step) {
				t.Fatalf("%s job %s step %q passes an app installation token to %s, and the code resolved from that ref after it moves can read the token", step.File, step.Job, step.Name, step.Uses)
			}
		})
	}
	if vulnerable == 0 {
		t.Log("every app-token action ref is a full commit SHA")
	}
}

// tokenVisibleAfterRefMoves publishes a benign action, points the step's ref at
// it, resolves that ref, then moves the ref to a different commit and resolves
// again. Only the second resolution is executed. That is the resolution the
// runner performs when it asks the service for the ref embedded in `uses` and
// then starts that commit's entrypoint with the step's inputs.
func tokenVisibleAfterRefMoves(t *testing.T, step tokenStep) bool {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}

	name, ref, actionPath := parseUses(step.Uses)
	if name == "" || ref == "" {
		t.Fatalf("unsupported uses %q", step.Uses)
	}

	repo := t.TempDir()
	run(t, repo, gitPath, "init", "-b", "fixture")
	benign := commitAction(t, repo, gitPath, actionPath, "benign", benignScript)
	malicious := commitAction(t, repo, gitPath, actionPath, "malicious", maliciousScript)

	if !fullSHA.MatchString(ref) {
		// First resolution, then the ref moves, then the runner resolves again
		// at download time. The first result must not be reused.
		pointRef(t, repo, gitPath, ref, benign)
		if got := resolveRef(t, repo, gitPath, ref); got != benign {
			t.Fatalf("ref %s resolved to %s, want the commit it was pointed at %s", ref, got, benign)
		}
		pointRef(t, repo, gitPath, ref, malicious)
	} else {
		// A tag or branch whose name is the pinned SHA must not redirect it.
		pointRef(t, repo, gitPath, ref, malicious)
	}

	resolved := resolveRef(t, repo, gitPath, ref)
	if resolved != malicious {
		return false
	}

	checkout := t.TempDir()
	run(t, repo, gitPath, "--git-dir="+filepath.Join(repo, ".git"), "--work-tree="+checkout, "checkout", "-f", malicious)

	manifestPath := filepath.Join(checkout, filepath.FromSlash(actionPath), "action.yml")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Runs struct {
			Using string `yaml:"using"`
			Main  string `yaml:"main"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	using := strings.ToLower(manifest.Runs.Using)
	if using != "node12" && using != "node16" && using != "node20" && using != "node24" {
		t.Fatalf("moved action runs.using = %q, node entrypoint required", manifest.Runs.Using)
	}
	if manifest.Runs.Main == "" {
		t.Fatal("moved action has no runs.main")
	}

	actionDir := filepath.Join(checkout, filepath.FromSlash(actionPath))
	script := filepath.Join(actionDir, filepath.FromSlash(manifest.Runs.Main))
	sink := filepath.Join(t.TempDir(), "sink")
	workspace := t.TempDir()
	env := runnerEnvironment(step, sink)
	cmd := exec.Command(nodePath, script)
	cmd.Dir = workspace
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node entrypoint: %v\n%s", err, out)
	}
	got, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	return string(got) == "seen"
}

func runnerEnvironment(step tokenStep, sink string) []string {
	env := []string{
		"SINK_PATH=" + sink,
		"NEEDLE=" + placeholderInstallationToken,
	}
	for key, value := range step.With {
		env = append(env, "INPUT_"+inputEnvName(key)+"="+evaluated(value, step.IDs))
	}
	for key, value := range step.Env {
		env = append(env, key+"="+evaluated(value, step.IDs))
	}
	return env
}

func inputEnvName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, " ", "_"))
}

func evaluated(value string, tokenIDs []string) string {
	if referencesToken(value, tokenIDs) {
		return placeholderInstallationToken
	}
	return value
}

func referencesToken(value string, tokenIDs []string) bool {
	for _, id := range tokenOutput.FindAllStringSubmatch(value, -1) {
		for _, want := range tokenIDs {
			if id[1] == want {
				return true
			}
		}
	}
	return false
}

// fullRef is the git ref a non-SHA action version is stored under.
// Version names are tags. Every other name is a branch. Both are movable refs,
// and each name is stored in only one namespace so rev-parse is unambiguous.
func fullRef(ref string) string {
	if len(ref) >= 2 && (ref[0] == 'v' || ref[0] == 'V') && ref[1] >= '0' && ref[1] <= '9' {
		return "refs/tags/" + ref
	}
	return "refs/heads/" + ref
}

func pointRef(t *testing.T, repo, gitPath, ref, sha string) {
	t.Helper()
	run(t, repo, gitPath, "update-ref", fullRef(ref), sha)
}

func resolveRef(t *testing.T, repo, gitPath, ref string) string {
	t.Helper()
	if fullSHA.MatchString(ref) {
		return strings.ToLower(ref)
	}
	out := run(t, repo, gitPath, "rev-parse", "--verify", fullRef(ref)+"^{commit}")
	return strings.TrimSpace(out)
}

func commitAction(t *testing.T, repo, gitPath, actionPath, message, script string) string {
	t.Helper()
	dir := filepath.Join(repo, filepath.FromSlash(actionPath))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: fixture\nruns:\n  using: node24\n  main: index.js\n"
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, gitPath, "add", "-A")
	run(t, repo, gitPath, "commit", "-m", message)
	return strings.TrimSpace(run(t, repo, gitPath, "rev-parse", "HEAD"))
}

func run(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	args = append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.com",
		"GIT_COMMITTER_NAME=fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func appTokenSteps(t *testing.T, root string) []tokenStep {
	t.Helper()
	var files []string
	for _, dir := range []string{filepath.Join(root, ".github", "workflows"), filepath.Join(root, ".github", "actions")} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := strings.ToLower(d.Name())
			if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	var steps []tokenStep
	for _, file := range files {
		steps = append(steps, stepsInFile(t, root, file)...)
	}
	return steps
}

func stepsInFile(t *testing.T, root, file string) []tokenStep {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Jobs map[string]struct {
			Steps []yamlStep `yaml:"steps"`
		} `yaml:"jobs"`
		Runs struct {
			Steps []yamlStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		t.Fatal(err)
	}
	var steps []tokenStep
	collect := func(jobName string, rawSteps []yamlStep) {
		var producers []string
		for i, step := range rawSteps {
			if strings.Contains(step.Uses, "create-github-app-token@") {
				id := step.ID
				if id == "" {
					id = fmt.Sprintf("step%d", i)
				}
				producers = append(producers, id)
			}
		}
		if len(producers) == 0 {
			return
		}
		for i, step := range rawSteps {
			if step.Uses == "" || strings.HasPrefix(step.Uses, "./") || strings.HasPrefix(step.Uses, ".\\") {
				continue
			}
			if !strings.Contains(step.Uses, "@") {
				continue
			}
			with := stringifyMap(step.With)
			env := stringifyMap(step.Env)
			blob := strings.Join(append(mapValues(with), mapValues(env)...), "\n")
			var ids []string
			for _, match := range tokenOutput.FindAllStringSubmatch(blob, -1) {
				for _, id := range producers {
					if match[1] == id {
						ids = append(ids, id)
					}
				}
			}
			if len(ids) == 0 {
				continue
			}
			name := step.Name
			if name == "" {
				name = step.ID
			}
			if name == "" {
				name = fmt.Sprintf("step-%d", i)
			}
			steps = append(steps, tokenStep{
				File: rel,
				Job:  jobName,
				Name: name,
				Uses: step.Uses,
				With: with,
				Env:  env,
				IDs:  ids,
			})
		}
	}
	for jobName, job := range doc.Jobs {
		collect(jobName, job.Steps)
	}
	if len(doc.Runs.Steps) > 0 {
		collect("runs", doc.Runs.Steps)
	}
	return steps
}

type yamlStep struct {
	Name string         `yaml:"name"`
	ID   string         `yaml:"id"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
}

func stringifyMap(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = fmt.Sprint(value)
	}
	return out
}

func mapValues(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for _, value := range in {
		out = append(out, value)
	}
	return out
}

func parseUses(uses string) (name, ref, actionPath string) {
	at := strings.LastIndex(uses, "@")
	repoPart := uses
	if at > 0 {
		ref = uses[at+1:]
		repoPart = uses[:at]
	}
	parts := strings.Split(repoPart, "/")
	if len(parts) >= 2 {
		name = parts[0] + "/" + parts[1]
		if len(parts) > 2 {
			actionPath = strings.Join(parts[2:], "/")
		}
		return name, ref, actionPath
	}
	return repoPart, ref, ""
}

func actionRef(uses string) string {
	_, ref, _ := parseUses(uses)
	return ref
}

func repoRoot(t *testing.T) string {
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

// benignScript is the commit the ref points at before the attacker moves it.
// The test resolves that commit and then discards the result.
const benignScript = `
const fs = require('fs');
fs.writeFileSync(process.env.SINK_PATH, 'benign');
`

// maliciousScript is the entrypoint published at the moved ref.
// getInput is the body of @actions/core 1.10.1, which actions/github-script v8
// uses to read the github-token input the runner put in the environment.
const maliciousScript = `
const fs = require('fs');
function getInput(name) {
  const val = process.env['INPUT_' + name.replace(/ /g, '_').toUpperCase()] || '';
  return val.trim();
}
const needle = process.env.NEEDLE;
function seenValue(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  return value === needle || value.trim() === needle.trim();
}
let seen = false;
for (const [key, value] of Object.entries(process.env)) {
  if (key === 'NEEDLE' || key === 'SINK_PATH') {
    continue;
  }
  if (seenValue(value)) {
    seen = true;
  }
  if (key.startsWith('INPUT_')) {
    const name = key.slice('INPUT_'.length).toLowerCase();
    if (seenValue(getInput(name))) {
      seen = true;
    }
  }
}
fs.writeFileSync(process.env.SINK_PATH, seen ? 'seen' : 'absent');
`
