"""Security tests for the Levitate breaking-change workflow.

These tests fail while a pull request checkout can run in a job that can mint
the plugins-data cloud token. They pass once that job executes only files from
the base checkout, and once step outputs are not inserted into the shell script.
"""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/detect-breaking-changes-levitate.yml"

# Obvious placeholder. Not a credential.
OIDC_REQUEST_TOKEN = "placeholder-oidc-request-token"
OIDC_REQUEST_URL = "https://example.invalid/actions-oidc-placeholder"
def load_workflow():
    data = yaml.safe_load(WORKFLOW_PATH.read_text())
    # YAML 1.1 parses the bare key "on" as boolean true.
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def id_token_write(permissions):
    if permissions == "write-all":
        return True
    if not isinstance(permissions, dict):
        return False
    return str(permissions.get("id-token", "")).strip("'\"") == "write"


def lookup(expr, ctx):
    expr = expr.strip()
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in ("'", '"'):
        return expr[1:-1]
    cur = ctx
    for part in expr.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(expr)
    return cur


def eval_if(condition, ctx):
    if condition is None:
        return True
    if isinstance(condition, bool):
        return condition
    text = str(condition).strip()
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    for op in ("==", "!="):
        if op in text:
            left, right = text.split(op, 1)
            try:
                match = lookup(left, ctx) == lookup(right, ctx)
            except KeyError:
                # A condition this harness cannot decide still runs the step.
                # Skipping it would hide pull-request code that GitHub runs.
                return True
            return match if op == "==" else not match
    return True


def checkout_kind(ref, ctx):
    """pull_request checkouts without an explicit base ref are the merge commit."""
    if ref is None or str(ref).strip() == "":
        return "pr"
    text = str(ref).strip()
    base_ref = ctx["github"]["event"]["pull_request"]["base"]["ref"]
    if text.startswith("${{") and text.endswith("}}"):
        value = lookup(text[3:-2], ctx)
        return "base" if value == base_ref else "pr"
    return "base" if text == base_ref else "pr"


def materialize(tree_root, workspace, dest_rel, origin, origins):
    dest_root = workspace if dest_rel in (None, "", ".") else os.path.join(workspace, dest_rel)
    for dirpath, _dirs, files in os.walk(tree_root):
        rel = os.path.relpath(dirpath, tree_root)
        target_dir = dest_root if rel == "." else os.path.join(dest_root, rel)
        os.makedirs(target_dir, exist_ok=True)
        for name in files:
            src = os.path.join(dirpath, name)
            dst = os.path.join(target_dir, name)
            shutil.copy2(src, dst)
            origins[os.path.abspath(dst)] = origin


def write_credentials_file(workspace, provider, service_account):
    """Same external-account file google-github-actions/auth@7c6bc770 writes."""
    audience = "https://iam.googleapis.com/%s" % provider
    request_url = OIDC_REQUEST_URL + "?audience=" + audience
    path = os.path.join(workspace, "gha-creds-0123456789abcdef.json")
    data = {
        "type": "external_account",
        "audience": "//iam.googleapis.com/%s" % provider,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/token",
        "credential_source": {
            "url": request_url,
            "headers": {"Authorization": "Bearer %s" % OIDC_REQUEST_TOKEN},
            "format": {"type": "json", "subject_token_field_name": "value"},
        },
        "service_account_impersonation_url": (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
            % service_account
        ),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return path


def bash_env(base_env):
    env = os.environ.copy()
    env.update(base_env)
    env["PATH"] = os.environ.get("PATH", "")
    return env


def run_bash(script_text, env, cwd):
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script_text)
        os.chmod(path, stat.S_IRWXU)
        subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", path],
            cwd=cwd,
            env=bash_env(env),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        os.remove(path)


def run_node(script_path, env, cwd):
    subprocess.run(
        ["node", script_path],
        cwd=cwd,
        env=bash_env(env),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def single_workspace_script(run_text, cwd):
    text = (run_text or "").strip()
    if not text or "\n" in text or " " in text or not text.startswith("./"):
        return None
    path = os.path.normpath(os.path.join(cwd, text))
    if os.path.isfile(path):
        return path
    return None


def local_action_dir(uses, workspace):
    if not isinstance(uses, str) or not uses.startswith("./"):
        return None
    return os.path.normpath(os.path.join(workspace, uses))


def required_local_modules(script_text):
    modules = []
    needle = "require("
    cursor = 0
    while True:
        start = script_text.find(needle, cursor)
        if start < 0:
            break
        rest = script_text[start + len(needle) :].lstrip()
        if not rest or rest[0] not in ("'", '"'):
            cursor = start + len(needle)
            continue
        quote = rest[0]
        end = rest.find(quote, 1)
        if end < 0:
            break
        spec = rest[1:end]
        if spec.startswith("."):
            modules.append(spec)
        cursor = start + len(needle) + end
    return modules


def probe_shell(source, log_path):
    recorder = "\n".join(
        [
            "import json, os",
            "oidc = 'present' if os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN') else 'absent'",
            "creds_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') or ''",
            "creds = 'readable' if creds_path and os.path.isfile(creds_path) else 'absent'",
            "record = {'source': %s, 'oidc': oidc, 'creds': creds}" % json.dumps(source),
            "open(%s, 'a').write(json.dumps(record) + '\\n')" % json.dumps(log_path),
        ]
    )
    return "#!/usr/bin/env bash\npython3 - <<'PY'\n" + recorder + "\nPY\n"


def probe_action(source, log_path):
    script = probe_shell(source, log_path).replace("#!/usr/bin/env bash\n", "")
    indented = textwrap.indent(script, "        ")
    return (
        "name: probe\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n" + indented
    )


def probe_js(source, log_path):
    return textwrap.dedent(
        """\
        const fs = require('fs');
        const oidc = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ? 'present' : 'absent';
        let creds = 'absent';
        const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || '';
        if (credPath) {
          try {
            fs.readFileSync(credPath);
            creds = 'readable';
          } catch (err) {}
        }
        fs.appendFileSync(%s, JSON.stringify({source: %s, oidc, creds}) + '\\n');
        module.exports = async () => {};
        """
        % (json.dumps(log_path), json.dumps(source))
    )


def make_trees(log_path):
    base = tempfile.mkdtemp(prefix="levitate-base-")
    pr = tempfile.mkdtemp(prefix="levitate-pr-")
    shutil.copytree(REPO_ROOT / ".github", os.path.join(base, ".github"))
    shutil.copytree(os.path.join(base, ".github"), os.path.join(pr, ".github"))
    replacements = {
        ".github/actions/setup-node/action.yml": probe_action("setup-node", log_path),
        ".github/actions/yarn-install/action.yml": probe_action("yarn-install", log_path),
        ".github/workflows/scripts/levitate/check-breaking-changes.sh": probe_shell(
            "check-breaking-changes.sh", log_path
        ),
        ".github/workflows/scripts/levitate/json-file-to-job-output.js": probe_js(
            "json-file-to-job-output.js", log_path
        ),
    }
    for rel, contents in replacements.items():
        path = os.path.join(pr, rel)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(contents)
        if path.endswith(".sh"):
            os.chmod(path, stat.S_IRWXU)
    return base, pr


def step_environment(job_env, mint_oidc):
    env = dict(job_env)
    if mint_oidc:
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = OIDC_REQUEST_URL
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST_TOKEN
    return env


def run_jobs(workflow, ctx, workspace, origins, observations, log_path):
    workflow_perms = workflow.get("permissions")
    for job in workflow["jobs"].values():
        if not eval_if(job.get("if"), ctx):
            continue
        perms = job.get("permissions", workflow_perms)
        mint_oidc = id_token_write(perms)
        job_env = {"GITHUB_WORKSPACE": workspace}
        defaults = ((job.get("defaults") or {}).get("run") or {}).get("working-directory") or "."
        for step in job.get("steps") or []:
            if not eval_if(step.get("if"), ctx):
                continue
            uses = step.get("uses") or ""
            step_env = step_environment(job_env, mint_oidc)
            cwd = workspace if defaults in (".", "") else os.path.join(workspace, defaults)
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                with_ = step.get("with") or {}
                kind = checkout_kind(with_.get("ref"), ctx)
                tree = ctx["trees"][kind]
                materialize(tree, workspace, with_.get("path") or ".", kind, origins)
                continue
            action_dir = local_action_dir(uses, workspace)
            if action_dir:
                manifest_path = os.path.join(action_dir, "action.yml")
                if not os.path.isfile(manifest_path):
                    manifest_path = os.path.join(action_dir, "action.yaml")
                origin = origins.get(os.path.abspath(manifest_path))
                if origin == "pr" and os.path.isfile(manifest_path):
                    manifest = yaml.safe_load(Path(manifest_path).read_text())
                    runs = (manifest or {}).get("runs") or {}
                    if runs.get("using") == "composite":
                        for action_step in runs.get("steps") or []:
                            if action_step.get("run"):
                                before = line_count(log_path)
                                run_bash(action_step["run"], step_env, cwd)
                                observations.extend(new_log_entries(log_path, before))
                continue
            if uses.startswith("google-github-actions/auth@"):
                # auth throws before writing a file when the OIDC request
                # variables are absent, which is the case without id-token: write.
                if not mint_oidc:
                    continue
                inputs = step.get("with") or {}
                cred_path = write_credentials_file(
                    workspace,
                    inputs.get("workload_identity_provider"),
                    inputs.get("service_account"),
                )
                job_env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] = cred_path
                job_env["GOOGLE_APPLICATION_CREDENTIALS"] = cred_path
                job_env["GOOGLE_GHA_CREDS_PATH"] = cred_path
                continue
            if uses.startswith("actions/github-script@"):
                script = ((step.get("with") or {}).get("script")) or ""
                for spec in required_local_modules(script):
                    module_path = os.path.normpath(os.path.join(workspace, spec))
                    origin = origins.get(os.path.abspath(module_path))
                    if origin != "pr":
                        continue
                    before = line_count(log_path)
                    run_node(module_path, step_env, workspace)
                    observations.extend(new_log_entries(log_path, before))
                continue
            script_path = single_workspace_script(step.get("run"), cwd)
            if script_path:
                origin = origins.get(os.path.abspath(script_path))
                if origin == "pr":
                    before = line_count(log_path)
                    run_bash(Path(script_path).read_text(), step_env, cwd)
                    observations.extend(new_log_entries(log_path, before))


def line_count(log_path):
    if not os.path.exists(log_path):
        return 0
    return len(Path(log_path).read_text().splitlines())


def new_log_entries(log_path, before):
    if not os.path.exists(log_path):
        return []
    lines = [line for line in Path(log_path).read_text().splitlines() if line.strip()]
    return [json.loads(line) for line in lines[before:]]


def observed_secret(observations):
    return [item for item in observations if item.get("oidc") == "present" or item.get("creds") == "readable"]


class LevitateBreakingChangeWorkflowTest(unittest.TestCase):
    def test_pull_request_checkout_cannot_observe_cloud_token(self):
        workflow = load_workflow()
        tmp = tempfile.mkdtemp(prefix="levitate-job-")
        log_path = os.path.join(tmp, "probe.log")
        base, pr = make_trees(log_path)
        workspace = os.path.join(tmp, "workspace")
        os.makedirs(workspace)
        ctx = {
            "github": {
                "repository": "grafana/grafana",
                "event": {
                    "pull_request": {
                        "number": 1,
                        "base": {"ref": "main"},
                        "head": {"repo": {"full_name": "grafana/grafana"}},
                    }
                },
            },
            "trees": {"base": base, "pr": pr},
        }
        observations = []
        try:
            run_jobs(workflow, ctx, workspace, {}, observations, log_path)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(pr, ignore_errors=True)
        leaked = observed_secret(observations)
        self.assertEqual(
            leaked,
            [],
            "pull request files ran in a job that held the OIDC request token or the Google credentials file: %s"
            % leaked,
        )

    def test_persisted_step_output_is_not_executed(self):
        workflow = load_workflow()
        step = next(
            step
            for step in workflow["jobs"]["Detect"]["steps"]
            if step.get("name") == "Persisting the check output"
        )
        marker = tempfile.mktemp(prefix="levitate-output-")
        payload = "$(touch %s)" % marker
        env = {}
        for key, value in (step.get("env") or {}).items():
            text = str(value)
            if "outputs.message" in text:
                env[key] = payload
            elif "outputs.is_breaking" in text:
                env[key] = "1"
            elif "pull_request.number" in text:
                env[key] = "1"
            else:
                env[key] = text
        run_text = step["run"]
        # Expressions written in the run script are part of the script text.
        # Expressions written only under env are process environment values.
        if "${{" in run_text:
            run_text = run_text.replace("${{ steps.breaking-changes.outputs.message }}", payload)
            run_text = run_text.replace("${{ steps.breaking-changes.outputs.is_breaking }}", "1")
            run_text = run_text.replace("${{ github.event.pull_request.number }}", "1")
        try:
            run_bash(run_text, env, tempfile.gettempdir())
            self.assertFalse(
                os.path.exists(marker),
                "persisting the breaking-change output executed a command from the step output",
            )
        finally:
            if os.path.exists(marker):
                os.remove(marker)


if __name__ == "__main__":
    unittest.main()
