package githubactions

// These tests exercise the Crowdin workflows' hand-off of the Vault-sourced
// Crowdin token to actions referenced by a branch name.
//
// They fail while that hand-off is present: a replacement commit on the
// referenced branch receives the token. They pass once every action that
// loads or receives the token is pinned to a full commit SHA, because a
// later move of the branch is not the commit the runner checks out.
//
// The runner behaviour modelled here is actions/runner v2.338.2:
//   - ActionManager.GetDownloadInfoAsync sends the uses ref to the service,
//     and DownloadRepositoryActionAsync unpacks the archive for ResolvedSha
//     (src/Runner.Worker/ActionManager.cs).
//   - CompositeActionHandler copies every with input into the inputs context
//     and evaluates each embedded step's env before the script runs
//     (src/Runner.Worker/Handlers/CompositeActionHandler.cs).
//   - ActionRunner keeps with keys that the action.yml does not declare
//     (src/Runner.Worker/ActionRunner.cs).
//   - ScriptHandler injects ACTIONS_ID_TOKEN_REQUEST_URL and
//     ACTIONS_ID_TOKEN_REQUEST_TOKEN for a script step when the job payload
//     carries GenerateIdTokenUrl, and runs bash as
//     "--noprofile --norc -e -o pipefail"
//     (src/Runner.Worker/Handlers/ScriptHandler.cs,
//     src/Runner.Worker/Handlers/ScriptHandlerHelpers.cs).
//   - SetOutputFileCommand / EnvFileKeyValuePairs parses GITHUB_OUTPUT,
//     including NAME<<DELIM heredocs
//     (src/Runner.Worker/FileCommandManager.cs).
//   - fromJSON / toJSON and property access are case-insensitive
//     (src/Sdk/DTExpressions2/.../FromJson.cs, ToJson.cs, Index.cs,
//     DictionaryContextData).
//
// Secret values in this file are placeholders. Nothing here calls Vault,
// Crowdin, or a GitHub Actions service.
//
// Left untested, same unpinned-vault pattern but different secrets:
//   .github/workflows/pr-build-grafana.yml
//   .github/workflows/pr-e2e-tests.yml
//   .github/workflows/release-build.yml
//   .github/workflows/community-release.yml
//   .github/workflows/issue-opened.yml
// actions/checkout in the Crowdin workflows does not receive the token.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	// Obvious placeholders. These are not credentials.
	placeholderCrowdinToken = "placeholder-crowdin-token"
	placeholderOIDCToken    = "placeholder-oidc-request-token"
	placeholderOIDCURL      = "https://oidc.example.invalid/request"

	productionRepository = "grafana/grafana"
	productionOwner      = "grafana"
)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// translateSecretsBash is grafana/shared-workflows actions/get-vault-secrets/translate-secrets.bash
// at shared-workflows commit 6a943082408bb241a26b14661e446220c3e62b16 (main when this test was written).
const translateSecretsBash = `#!/usr/bin/env bash

# Input env:
# - VERSION => vault-secrets schema version (v1 or v2). Selects the Vault mount:
#     v1 uses the shared ` + "`ci`" + ` mount; v2 uses a per-org ` + "`ci-${REPO_OWNER}`" + ` mount.
# - REPO => Repository name (owner/repo)
# - REPO_OWNER => Repository owner/org (only required for v2)
# - COMMON_SECRETS => Common secrets (in the <mount>/data/common/<path> vault path): {{ Env Variable Name }}={{ Secret Path }}:{{ Secret Key }}
# - REPO_SECRETS => Repo secrets (in the <mount>/data/repo/${REPO}/<path> vault path): {{ Env Variable Name }}={{ Secret Path }}:{{ Secret Key }}
# Output format: "{{ Secret Path }} {{ Secret Key }} | {{ Env Variable Name }}" in the $GITHUB_OUTPUT file

if [ -z "$REPO" ]; then
	echo "Error: REPO environment variable is not set."
	exit 1
fi

if [ -z "$GITHUB_OUTPUT" ]; then
	echo "Error: GITHUB_OUTPUT environment variable is not set."
	exit 1
fi

if [ "$VERSION" = "v2" ]; then
	if [ -z "$REPO_OWNER" ]; then
		echo "Error: REPO_OWNER environment variable is not set."
		exit 1
	fi
	MOUNT="ci-${REPO_OWNER}"
else
	MOUNT="ci"
fi

readonly COMMON_SECRETS GITHUB_OUTPUT MOUNT REPO REPO_OWNER REPO_SECRETS VERSION

RESULT=""

split_string() {
	local input_string="$1"
	IFS='=' read -ra parts <<<"$input_string"

	if [ "${#parts[@]}" -eq 2 ]; then
		env_variable_name="${parts[0]}"
		secret_parts="${parts[1]}"

		IFS=':' read -ra secret_parts <<<"$secret_parts"

		if [ "${#secret_parts[@]}" -eq 2 ]; then
			secret_path="${secret_parts[0]}"
			secret_key="${secret_parts[1]}"
		fi
	fi
}

if [ -n "$COMMON_SECRETS" ]; then
	for common_secret in $COMMON_SECRETS; do
		split_string "$common_secret"
		RESULT="${RESULT}${MOUNT}/data/common/$secret_path $secret_key | $env_variable_name;\n"
	done
fi

if [ -n "$REPO_SECRETS" ]; then
	for repo_secret in $REPO_SECRETS; do
		split_string "$repo_secret"
		RESULT="${RESULT}${MOUNT}/data/repo/$REPO/$secret_path $secret_key | $env_variable_name;\n"
	done
fi

readonly RESULT

echo -e "Secrets that will be queried from Vault:\n$RESULT"
echo -e "secrets<<EOF\n${RESULT}EOF" >"$GITHUB_OUTPUT"
`

// extractPy is the stand-in for hashicorp/vault-action v4.0.0
// (892a26828f195e65540a40b4768ae4571f51ebfc): parseSecretsInput in src/action.js,
// the KV-v2 selector prefix in src/secrets.js selectAndAppendResults, and the
// GITHUB_OUTPUT heredoc grammar in EnvFileKeyValuePairs.
const extractPy = `import json, sys

def parse_env_file(text):
    pairs = []
    index = 0
    def read_line(index):
        if index >= len(text):
            return None, None, index
        lf = text.find("\n", index)
        if lf < 0:
            return text[index:], None, len(text)
        return text[index:lf], "\n", lf + 1
    line, _, index = read_line(index)
    while line is not None:
        if line != "":
            equals = line.find("=")
            heredoc = line.find("<<")
            if equals >= 0 and (heredoc < 0 or equals < heredoc):
                key, output = line.split("=", 1)
            elif heredoc >= 0 and (equals < 0 or heredoc < equals):
                key, delimiter = line.split("<<", 1)
                if key == "" or delimiter == "":
                    raise SystemExit("invalid heredoc header")
                start = index
                end = index
                temp, newline, index = read_line(index)
                while temp != delimiter:
                    if temp is None:
                        raise SystemExit("missing heredoc delimiter")
                    if newline is None:
                        raise SystemExit("eof marker missing newline")
                    end = index - len(newline)
                    temp, newline, index = read_line(index)
                output = text[start:end] if end > start else ""
            else:
                raise SystemExit("invalid output line %r" % line)
            pairs.append((key, output))
        line, _, index = read_line(index)
    return pairs

def parse_secrets(spec):
    found = []
    for secret in spec.split(";"):
        secret = secret.strip()
        if not secret:
            continue
        rename = secret.rfind("|")
        if rename < 0:
            raise SystemExit("secret missing output name")
        path_spec = secret[:rename].strip()
        output_name = secret[rename + 1:].strip()
        parts = path_spec.split()
        if len(parts) != 2:
            raise SystemExit("secret path/key invalid: %r" % secret)
        path, selector = parts
        selector = selector.replace('"', "")
        found.append((path, selector, output_name))
    return found

def select_kv(body, selector):
    # secrets.js wraps a simple selector in quotes and prefixes data. twice
    # when the Vault response is KV v2 (body.data.data is present).
    if "." not in selector:
        selector = '"' + selector + '"'
    selector = "data." + selector
    data = body["data"]
    if isinstance(data, dict) and "data" in data:
        selector = "data." + selector
        data = data["data"]
    key = selector.split(".")[-1].strip('"')
    if key not in data:
        raise SystemExit("selector %s missing in vault response" % key)
    return data[key]

def main():
    spec = open(sys.argv[1]).read()
    body = json.load(open(sys.argv[2]))
    pairs = parse_env_file(spec)
    secrets = ""
    for key, value in pairs:
        if key == "secrets":
            secrets = value
    requests = parse_secrets(secrets)
    if len(requests) != 1:
        raise SystemExit("expected one secret request, got %d" % len(requests))
    path, selector, output_name = requests[0]
    if path != "ci/data/repo/grafana/grafana/grafana-frontend-crowdin-token":
        raise SystemExit("unexpected vault path %s" % path)
    if selector != "access_token":
        raise SystemExit("unexpected selector %s" % selector)
    value = select_kv(body, selector)
    sys.stdout.write(output_name + "\n" + value)

if __name__ == "__main__":
    main()
`

func TestVaultResponseSelectsCrowdinToken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "translate-secrets.bash"), translateSecretsBash)
	writeFile(t, filepath.Join(dir, "extract.py"), extractPy)
	fixture := filepath.Join(dir, "vault.json")
	writeFile(t, fixture, `{"data":{"data":{"access_token":"`+placeholderCrowdinToken+`"}}}`+"\n")
	spec := filepath.Join(dir, "spec.txt")
	cmd := exec.Command("bash", filepath.Join(dir, "translate-secrets.bash"))
	cmd.Env = append(os.Environ(),
		"GITHUB_OUTPUT="+spec,
		"REPO="+productionRepository,
		"REPO_OWNER="+productionOwner,
		"VERSION=v1",
		"REPO_SECRETS=\nCROWDIN_TOKEN=grafana-frontend-crowdin-token:access_token\n",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("translate-secrets.bash: %v\n%s", err, out)
	}
	extract := exec.Command("python3", filepath.Join(dir, "extract.py"), spec, fixture)
	out, err := extract.CombinedOutput()
	if err != nil {
		t.Fatalf("extract.py: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "CROWDIN_TOKEN" || lines[1] != placeholderCrowdinToken {
		t.Fatalf("vault select = %q", out)
	}
}

func TestMutableActionRefDoesNotReceiveCrowdinToken(t *testing.T) {
	root := moduleRoot(t)
	workflows := []string{
		".github/workflows/i18n-crowdin-create-tasks.yml",
		".github/workflows/i18n-crowdin-download.yml",
		".github/workflows/i18n-crowdin-upload.yml",
	}
	for _, rel := range workflows {
		for _, target := range []string{"vault", "consumer"} {
			t.Run(rel+"/"+target, func(t *testing.T) {
				sink, produced := runWorkflow(t, filepath.Join(root, rel), target)
				if !produced {
					t.Fatal("vault step did not produce the crowdin token, so the hand-off was not exercised")
				}
				if strings.Contains(sink, placeholderCrowdinToken) {
					t.Fatalf("replacement on the moving ref received the crowdin token:\n%s", sink)
				}
			})
		}
	}
}

func TestPinnedRefsDoNotDeliverCrowdinToken(t *testing.T) {
	root := moduleRoot(t)
	workflows := []string{
		".github/workflows/i18n-crowdin-create-tasks.yml",
		".github/workflows/i18n-crowdin-download.yml",
		".github/workflows/i18n-crowdin-upload.yml",
	}
	const pinned = "0123456789abcdef0123456789abcdef01234567"
	for _, rel := range workflows {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		// A full SHA is not a branch. main of the local action repos still
		// points at the replacement commit; the runner must not check it out.
		pinnedBody := strings.ReplaceAll(string(body), "@main", "@"+pinned)
		path := filepath.Join(t.TempDir(), "workflow.yml")
		writeFile(t, path, pinnedBody)
		for _, target := range []string{"vault", "consumer"} {
			t.Run(rel+"/"+target, func(t *testing.T) {
				sink, produced := runWorkflow(t, path, target)
				if !produced {
					t.Fatal("pinned vault step did not produce the crowdin token")
				}
				if strings.Contains(sink, placeholderCrowdinToken) {
					t.Fatalf("sha pin still delivered the token to the replacement commit:\n%s", sink)
				}
			})
		}
	}
}

// runWorkflow runs one Crowdin workflow against local action repos.
// target "vault" points get-vault-secrets' branch at a commit that keeps the
// token. target "consumer" points the crowdin action's branch at a commit
// that records every input. The other action's branch stays on a commit that
// does not record the token.
func runWorkflow(t *testing.T, workflowPath, target string) (sink string, produced bool) {
	t.Helper()
	vaultRepo := buildActionRepo(t, vaultFiles(), target == "vault")
	consumerRepo := buildActionRepo(t, consumerFiles(), target == "consumer")
	repos := map[string]string{
		"grafana/shared-workflows":       vaultRepo,
		"grafana/grafana-github-actions": consumerRepo,
	}
	sinkFile := filepath.Join(t.TempDir(), "sink")
	writeFile(t, sinkFile, "")
	fixture := filepath.Join(t.TempDir(), "vault.json")
	writeFile(t, fixture, `{"data":{"data":{"access_token":"`+placeholderCrowdinToken+`"}}}`+"\n")

	var doc map[string]any
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	jobs, _ := doc["jobs"].(map[string]any)
	if len(jobs) == 0 {
		t.Fatalf("no jobs in %s", workflowPath)
	}
	github := map[string]any{
		"repository":       productionRepository,
		"repository_owner": productionOwner,
	}
	for name, jobRaw := range jobs {
		job, ok := jobRaw.(map[string]any)
		if !ok {
			t.Fatalf("job %s is not a mapping", name)
		}
		if cond, ok := job["if"].(string); ok {
			pass, err := evalTruthy(cond, map[string]any{"github": github})
			if err != nil {
				t.Fatalf("job if: %v", err)
			}
			if !pass {
				t.Fatalf("job %s was skipped; the production repository path did not run", name)
			}
		}
		idToken := permissionWrite(job, "id-token")
		steps, _ := job["steps"].([]any)
		jobSteps := map[string]any{}
		for _, stepRaw := range steps {
			step, ok := stepRaw.(map[string]any)
			if !ok {
				continue
			}
			uses, _ := step["uses"].(string)
			if uses == "" {
				continue
			}
			owner, repo, actionPath, ref, ok := parseUses(uses)
			if !ok {
				t.Fatalf("unparsed uses %q", uses)
			}
			kind := actionKind(owner, repo, actionPath)
			if kind == kindOther {
				continue
			}
			local := repos[owner+"/"+repo]
			sha, mutable := resolveRef(t, local, ref)
			var actionDir string
			if mutable || commitExists(t, local, sha) {
				actionDir = filepath.Join(checkout(t, local, sha), actionPath)
				_, captureErr := os.Stat(filepath.Join(actionDir, "CAPTURE"))
				wantCapture := (kind == kindVault && target == "vault") || (kind == kindConsumer && target == "consumer")
				if mutable && wantCapture && captureErr != nil {
					t.Fatalf("moving ref %s of %s resolved to %s, which is not the replacement commit", ref, uses, sha)
				}
				if mutable && !wantCapture && captureErr == nil {
					t.Fatalf("moving ref %s of %s resolved to the replacement commit in the other scenario", ref, uses)
				}
			} else if !fullSHA.MatchString(ref) {
				t.Fatalf("ref %q is not a full sha and could not be resolved", ref)
			} else {
				actionDir = writeStandIn(t, kind)
			}
			inputs := evalInputs(t, step["with"], map[string]any{
				"github": github,
				"steps":  jobSteps,
			})
			if kind == kindConsumer {
				if inputs["crowdin_token"] != placeholderCrowdinToken {
					t.Fatalf("crowdin_token input evaluated to %q; the vault output was not passed through", inputs["crowdin_token"])
				}
			}
			outputs := runComposite(t, actionDir, inputs, github, idToken, sinkFile, fixture)
			if id, _ := step["id"].(string); id != "" {
				jobSteps[id] = map[string]any{"outputs": stringMap(outputs)}
			}
			if kind == kindVault {
				secrets, _ := outputs["secrets"]
				if got := indexFromJSON(t, secrets, "CROWDIN_TOKEN"); got == placeholderCrowdinToken {
					produced = true
				}
			}
		}
	}
	sinkBytes, err := os.ReadFile(sinkFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(sinkBytes), produced
}

type kind int

const (
	kindOther kind = iota
	kindVault
	kindConsumer
)

func actionKind(owner, repo, actionPath string) kind {
	switch {
	case owner == "grafana" && repo == "shared-workflows" && actionPath == "actions/get-vault-secrets":
		return kindVault
	case owner == "grafana" && repo == "grafana-github-actions" && strings.HasPrefix(actionPath, "crowdin-"):
		return kindConsumer
	default:
		return kindOther
	}
}

func parseUses(uses string) (owner, repo, actionPath, ref string, ok bool) {
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return "", "", "", "", false
	}
	ref = uses[at+1:]
	parts := strings.Split(uses[:at], "/")
	if len(parts) < 2 {
		return "", "", "", "", false
	}
	owner, repo = parts[0], parts[1]
	if len(parts) > 2 {
		actionPath = strings.Join(parts[2:], "/")
	}
	return owner, repo, actionPath, ref, true
}

func permissionWrite(job map[string]any, name string) bool {
	perms, _ := job["permissions"].(map[string]any)
	return fmt.Sprint(perms[name]) == "write"
}

func evalInputs(t *testing.T, with any, root map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	mapping, _ := with.(map[string]any)
	for key, raw := range mapping {
		text := scalarString(raw)
		val, err := evalTemplate(text, root)
		if err != nil {
			t.Fatalf("input %s: %v", key, err)
		}
		out[key] = val
	}
	return out
}

func runComposite(t *testing.T, actionDir string, inputs map[string]string, github map[string]any, idToken bool, sink, fixture string) map[string]string {
	t.Helper()
	var action map[string]any
	raw, err := os.ReadFile(filepath.Join(actionDir, "action.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	inputs = applyInputDefaults(action, inputs)
	runs, _ := action["runs"].(map[string]any)
	if fmt.Sprint(runs["using"]) != "composite" {
		t.Fatalf("%s is not a composite action", actionDir)
	}
	steps, _ := runs["steps"].([]any)
	inner := map[string]any{}
	for _, stepRaw := range steps {
		step, _ := stepRaw.(map[string]any)
		root := map[string]any{
			"inputs": stringMap(inputs),
			"github": github,
			"steps":  inner,
		}
		env := map[string]string{}
		if envRaw, ok := step["env"].(map[string]any); ok {
			for key, raw := range envRaw {
				val, err := evalTemplate(scalarString(raw), root)
				if err != nil {
					t.Fatalf("env %s: %v", key, err)
				}
				env[key] = val
			}
		}
		runBody := scalarString(step["run"])
		if runBody == "" {
			t.Fatal("composite step has no run body")
		}
		outputFile := filepath.Join(t.TempDir(), "github-output")
		writeFile(t, outputFile, "")
		script := filepath.Join(t.TempDir(), "step.sh")
		writeFile(t, script, runBody)
		cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", script)
		cmd.Dir = actionDir
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"GITHUB_ACTION_PATH=" + actionDir,
			"GITHUB_OUTPUT=" + outputFile,
			"CAPTURE_SINK=" + sink,
			"VAULT_FIXTURE=" + fixture,
		}
		for key, val := range env {
			cmd.Env = append(cmd.Env, key+"="+val)
		}
		// ScriptHandler sets these when the job connection has GenerateIdTokenUrl.
		// get-id-token.js refuses to continue when they are absent, which it
		// attributes to a missing id-token: write permission.
		if idToken {
			cmd.Env = append(cmd.Env,
				"ACTIONS_ID_TOKEN_REQUEST_URL="+placeholderOIDCURL,
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+placeholderOIDCToken,
			)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("composite step failed: %v\n%s", err, out)
		}
		pairs := parseEnvFile(t, outputFile)
		stepOutputs := map[string]any{}
		for _, pair := range pairs {
			stepOutputs[pair[0]] = pair[1]
		}
		if id, _ := step["id"].(string); id != "" {
			inner[id] = map[string]any{"outputs": stepOutputs}
		}
	}
	actionOutputs := map[string]string{}
	if declared, ok := action["outputs"].(map[string]any); ok {
		root := map[string]any{
			"inputs": stringMap(inputs),
			"github": github,
			"steps":  inner,
		}
		for name, specRaw := range declared {
			spec, _ := specRaw.(map[string]any)
			val, err := evalTemplate(scalarString(spec["value"]), root)
			if err != nil {
				t.Fatalf("output %s: %v", name, err)
			}
			actionOutputs[name] = val
		}
	}
	return actionOutputs
}

func applyInputDefaults(action map[string]any, inputs map[string]string) map[string]string {
	out := map[string]string{}
	for key, val := range inputs {
		out[key] = val
	}
	declared, _ := action["inputs"].(map[string]any)
	for name, specRaw := range declared {
		if _, ok := lookupFold(out, name); ok {
			continue
		}
		spec, _ := specRaw.(map[string]any)
		if def, ok := spec["default"]; ok {
			out[name] = scalarString(def)
		}
	}
	return out
}

func lookupFold(m map[string]string, key string) (string, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func indexFromJSON(t *testing.T, raw, key string) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return ""
	}
	if v, ok := lookupAny(obj, key); ok {
		return scalarString(v)
	}
	return ""
}

func stringMap(in map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func evalTemplate(text string, root map[string]any) (string, error) {
	var b strings.Builder
	for {
		start := strings.Index(text, "${{")
		if start < 0 {
			b.WriteString(text)
			break
		}
		b.WriteString(text[:start])
		rest := text[start+3:]
		end := strings.Index(rest, "}}")
		if end < 0 {
			return "", fmt.Errorf("unclosed expression in %q", text)
		}
		val, err := evalExpr(strings.TrimSpace(rest[:end]), root)
		if err != nil {
			return "", err
		}
		b.WriteString(stringify(val))
		text = rest[end+2:]
	}
	return b.String(), nil
}

func evalTruthy(expr string, root map[string]any) (bool, error) {
	val, err := evalExpr(expr, root)
	if err != nil {
		return false, err
	}
	return val == true, nil
}

func evalExpr(expr string, root map[string]any) (any, error) {
	p := &exprParser{s: strings.TrimSpace(expr), root: root}
	val, err := p.parseCmp()
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing %q in %q", p.s[p.i:], expr)
	}
	return val, nil
}

type exprParser struct {
	s    string
	i    int
	root map[string]any
}

func (p *exprParser) parseCmp() (any, error) {
	left, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skip()
	if strings.HasPrefix(p.s[p.i:], "==") {
		p.i += 2
		right, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return stringify(left) == stringify(right), nil
	}
	return left, nil
}

func (p *exprParser) parseValue() (any, error) {
	p.skip()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("empty expression")
	}
	if p.s[p.i] == '\'' {
		return p.parseString(), nil
	}
	name := p.readIdent()
	if name == "" {
		return nil, fmt.Errorf("expected value at %q", p.s[p.i:])
	}
	var cur any
	p.skip()
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		var args []any
		for {
			p.skip()
			if p.i < len(p.s) && p.s[p.i] == ')' {
				p.i++
				break
			}
			arg, err := p.parseValue()
			if err != nil {
				return nil, err
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
			return nil, fmt.Errorf("expected ) after arguments")
		}
		out, err := callFn(name, args)
		if err != nil {
			return nil, err
		}
		cur = out
	} else {
		val, ok := lookupAny(p.root, name)
		if !ok {
			return nil, fmt.Errorf("unknown context %s", name)
		}
		cur = val
	}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '.' {
			return cur, nil
		}
		p.i++
		prop := p.readIdent()
		if prop == "" {
			return nil, fmt.Errorf("expected property name")
		}
		cur = indexProp(cur, prop)
	}
}

func (p *exprParser) parseString() string {
	p.i++ // opening quote
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != '\'' {
		p.i++
	}
	val := p.s[start:p.i]
	if p.i < len(p.s) {
		p.i++
	}
	return val
}

func (p *exprParser) readIdent() string {
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

func (p *exprParser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n') {
		p.i++
	}
}

func callFn(name string, args []any) (any, error) {
	switch strings.ToLower(name) {
	case "fromjson":
		if len(args) != 1 {
			return nil, fmt.Errorf("fromJSON expects 1 arg")
		}
		var parsed any
		if err := json.Unmarshal([]byte(stringify(args[0])), &parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	case "tojson":
		if len(args) != 1 {
			return nil, fmt.Errorf("toJSON expects 1 arg")
		}
		buf, err := json.Marshal(args[0])
		if err != nil {
			return nil, err
		}
		return string(buf), nil
	default:
		return nil, fmt.Errorf("unsupported function %s", name)
	}
}

func indexProp(cur any, prop string) any {
	switch obj := cur.(type) {
	case map[string]any:
		if v, ok := lookupAny(obj, prop); ok {
			return v
		}
	}
	return nil
}

func lookupAny(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		buf, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(buf)
	}
}

func parseEnvFile(t *testing.T, path string) [][2]string {
	t.Helper()
	textBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(textBytes)
	var pairs [][2]string
	index := 0
	readLine := func() (string, string, bool) {
		if index >= len(text) {
			return "", "", false
		}
		lf := strings.Index(text[index:], "\n")
		if lf < 0 {
			line := text[index:]
			index = len(text)
			return line, "", true
		}
		line := text[index : index+lf]
		index += lf + 1
		return line, "\n", true
	}
	for {
		line, _, ok := readLine()
		if !ok {
			break
		}
		if line == "" {
			continue
		}
		equals := strings.Index(line, "=")
		heredoc := strings.Index(line, "<<")
		switch {
		case equals >= 0 && (heredoc < 0 || equals < heredoc):
			parts := strings.SplitN(line, "=", 2)
			pairs = append(pairs, [2]string{parts[0], parts[1]})
		case heredoc >= 0 && (equals < 0 || heredoc < equals):
			parts := strings.SplitN(line, "<<", 2)
			key, delimiter := parts[0], parts[1]
			start := index
			end := index
			for {
				temp, newline, ok := readLine()
				if !ok || temp == delimiter && !ok {
					t.Fatalf("missing delimiter %s", delimiter)
				}
				if temp == delimiter {
					break
				}
				if newline == "" {
					t.Fatal("heredoc missing newline")
				}
				end = index - len(newline)
			}
			output := ""
			if end > start {
				output = text[start:end]
			}
			pairs = append(pairs, [2]string{key, output})
		default:
			t.Fatalf("invalid output line %q", line)
		}
	}
	return pairs
}

func vaultFiles() map[string]string {
	base := "actions/get-vault-secrets/"
	return map[string]string{
		base + "action.yaml":            vaultActionYAML,
		base + "translate-secrets.bash": translateSecretsBash,
		base + "extract.py":             extractPy,
		base + "read.sh":                vaultReadSH,
	}
}

func consumerFiles() map[string]string {
	files := map[string]string{}
	for _, dir := range []string{"crowdin-create-tasks", "crowdin-download", "crowdin-upload"} {
		files[dir+"/action.yaml"] = consumerActionYAML
		files[dir+"/keep.sh"] = consumerKeepSH
	}
	return files
}

const vaultActionYAML = `name: Get Vault Secrets
description: Test stand-in for the composite vault action output contract.
inputs:
  version:
    default: v1
  repo_secrets:
  common_secrets:
  vault_instance:
    default: ops
  ignore_missing:
    default: "false"
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
        COMMON_SECRETS: ${{ inputs.common_secrets }}
        REPO: ${{ github.repository }}
        REPO_OWNER: ${{ github.repository_owner }}
        VERSION: ${{ inputs.version }}
      run: bash "$GITHUB_ACTION_PATH/read.sh"
`

const vaultReadSH = `#!/usr/bin/env bash
set -euo pipefail
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
	echo "OIDC request credentials were not injected into the action script" >&2
	exit 1
fi
spec=$(mktemp)
GITHUB_OUTPUT="$spec" bash "$GITHUB_ACTION_PATH/translate-secrets.bash" >/dev/null
parsed=$(python3 "$GITHUB_ACTION_PATH/extract.py" "$spec" "$VAULT_FIXTURE")
output_name=${parsed%%$'\n'*}
token=${parsed#*$'\n'}
if [ -z "$token" ] || [ -z "$output_name" ]; then
	echo "vault response did not yield a token" >&2
	exit 1
fi
printf '%s=%s\n' "$output_name" "$token" >"$GITHUB_OUTPUT"
if [ -f "$GITHUB_ACTION_PATH/CAPTURE" ]; then
	printf '%s\n' "$token" >>"$CAPTURE_SINK"
fi
`

const consumerActionYAML = `name: Crowdin action
description: Test stand-in that can record every input the workflow passed.
inputs:
  crowdin_token:
  crowdin_project_id:
  pr_labels:
  github_board_id:
  en_paths:
  github_repo_token:
  github_pr_approver_token:
runs:
  using: composite
  steps:
    - shell: bash
      env:
        ALL_INPUTS: ${{ toJSON(inputs) }}
      run: bash "$GITHUB_ACTION_PATH/keep.sh"
`

const consumerKeepSH = `#!/usr/bin/env bash
set -euo pipefail
if [ -f "$GITHUB_ACTION_PATH/CAPTURE" ]; then
	printf '%s\n' "$ALL_INPUTS" >>"$CAPTURE_SINK"
fi
`

func writeStandIn(t *testing.T, k kind) string {
	t.Helper()
	dir := t.TempDir()
	var files map[string]string
	switch k {
	case kindVault:
		files = vaultFiles()
		// Stand-in is the action directory itself, not the repo root.
		for name, body := range files {
			writeFile(t, filepath.Join(dir, strings.TrimPrefix(name, "actions/get-vault-secrets/")), body)
		}
		return dir
	case kindConsumer:
		files = map[string]string{
			"action.yaml": consumerActionYAML,
			"keep.sh":     consumerKeepSH,
		}
		for name, body := range files {
			writeFile(t, filepath.Join(dir, name), body)
		}
		return dir
	default:
		t.Fatalf("no stand-in for kind %d", k)
		return ""
	}
}

func buildActionRepo(t *testing.T, files map[string]string, mainIsCapturer bool) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	writeTree(t, dir, files)
	benign := gitCommit(t, dir, "benign action")
	writeFile(t, filepath.Join(dir, "CAPTURE"), "")
	// CAPTURE lives next to each action.yaml so the checked-out action sees it.
	for name := range files {
		if strings.HasSuffix(name, "action.yaml") {
			capturePath := filepath.Join(dir, filepath.Dir(name), "CAPTURE")
			writeFile(t, capturePath, "")
		}
	}
	os.Remove(filepath.Join(dir, "CAPTURE"))
	capturer := gitCommit(t, dir, "replacement that keeps the token")
	mainSHA := benign
	if mainIsCapturer {
		mainSHA = capturer
	}
	git(t, dir, "update-ref", "refs/heads/main", mainSHA)
	return dir
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		writeFile(t, filepath.Join(dir, name), body)
	}
}

func resolveRef(t *testing.T, repo, ref string) (sha string, mutable bool) {
	t.Helper()
	if fullSHA.MatchString(ref) {
		return ref, false
	}
	// A branch or tag is resolved to whatever commit it names at job start.
	// Point that name at the commit buildActionRepo left on main, which is
	// either the replacement or the benign commit for this scenario.
	tip := strings.TrimSpace(git(t, repo, "rev-parse", "refs/heads/main"))
	git(t, repo, "update-ref", "refs/heads/"+ref, tip)
	resolved := strings.TrimSpace(git(t, repo, "rev-parse", "refs/heads/"+ref))
	return resolved, true
}

func commitExists(t *testing.T, repo, sha string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "cat-file", "-e", sha+"^{commit}")
	cmd.Env = gitEnv()
	return cmd.Run() == nil
}

func checkout(t *testing.T, repo, sha string) string {
	t.Helper()
	dest := t.TempDir()
	cmd := exec.Command("git", "clone", "--shared", repo, dest)
	cmd.Env = gitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	git(t, dest, "checkout", "--detach", sha)
	return dest
}

func gitCommit(t *testing.T, dir, message string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "-c", "commit.gpgsign=false", "commit", "-m", message)
	return strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=commit.gpgsign",
		"GIT_CONFIG_VALUE_0=false",
	)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}
