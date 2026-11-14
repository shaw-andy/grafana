"""Credential delivery to an unpinned GitHub Action.

These tests fail while a workflow passes a CI credential into an action whose
`uses` ref is not a full commit SHA, or runs that action in a job with
`id-token: write`. They pass once every such step is pinned to a full SHA or
no longer receives the credential and the OIDC permission.

Run:

    python3 pkg/tests/githubactions/test_unpinned_action_credential.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

APP_TOKEN = "APP_INSTALLATION_TOKEN_PLACEHOLDER"
GITHUB_TOKEN = "GITHUB_TOKEN_PLACEHOLDER"
VAULT_SECRET = "VAULT_SECRET_PLACEHOLDER"
SECRET_VALUE = "SECRET_VALUE_PLACEHOLDER"
OIDC_REQUEST = "OIDC_REQUEST_PLACEHOLDER"
OIDC_RESPONSE = "OIDC_RESPONSE_PLACEHOLDER"
PLACEHOLDERS = {
    APP_TOKEN,
    GITHUB_TOKEN,
    VAULT_SECRET,
    SECRET_VALUE,
    OIDC_REQUEST,
    OIDC_RESPONSE,
}

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
STATUS_FN_RE = re.compile(r"\b(success|failure|always|cancelled)\s*\(", re.IGNORECASE)
CREDENTIAL_RE = re.compile(r"secrets\.|github\.token|outputs\.token|fromJSON\(", re.IGNORECASE)
OFFICIAL_OWNERS = {"actions", "github"}

CAPTURE_JS = r"""
const fs = require('fs');
const capturePath = process.argv[2];

function getInput(name) {
  const val = process.env['INPUT_' + name.replace(/ /g, '_').toUpperCase()] || '';
  return val.trim();
}

function getIDToken() {
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const runtimeUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  if (!requestToken || !runtimeUrl) {
    return Promise.resolve('');
  }
  return fetch(runtimeUrl, {headers: {Authorization: 'Bearer ' + requestToken}})
    .then((res) => res.json())
    .then((body) => (body && body.value) || '');
}

const inputs = {};
for (const [key, value] of Object.entries(process.env)) {
  if (key.startsWith('INPUT_')) {
    inputs[key] = value;
  }
}
inputs.TOKEN_VIA_GETINPUT = getInput('token');

getIDToken().then((oidc) => {
  fs.writeFileSync(capturePath, JSON.stringify({inputs, oidc, envToken: process.env.LEAKED_TOKEN || ''}));
}).catch((err) => {
  fs.writeFileSync(capturePath, JSON.stringify({inputs, oidc: '', error: String(err), envToken: process.env.LEAKED_TOKEN || ''}));
});
"""


def load_workflow(path: Path) -> dict:
    # PyYAML 1.1 parses the bare key `on` as boolean true.
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise AssertionError(f"{path} did not parse as a mapping")
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def parse_uses(uses: str):
    """Match actions/runner ActionManifestManagerWrapper.ParseActionReference."""
    if not isinstance(uses, str):
        return None
    if uses.startswith("./") or uses.startswith(".\\") or uses.startswith("docker://"):
        return None
    at = uses.rfind("@")
    if at <= 0:
        return None
    ref = uses[at + 1 :]
    rest = uses[:at]
    parts = [part for part in rest.split("/") if part]
    if len(parts) < 2:
        return None
    return {
        "name": f"{parts[0]}/{parts[1]}",
        "owner": parts[0],
        "path": "/".join(parts[2:]),
        "ref": ref,
        "uses": uses,
    }


def is_full_sha(ref: str) -> bool:
    return bool(SHA_RE.fullmatch(ref or ""))


def id_token_write(perms) -> bool:
    if perms == "write-all":
        return True
    if isinstance(perms, dict):
        return perms.get("id-token") == "write"
    return False


def effective_permissions(workflow: dict, job: dict):
    if "permissions" in job:
        return job.get("permissions")
    return workflow.get("permissions")


def contains_credential(value) -> bool:
    if value is None:
        return False
    return bool(CREDENTIAL_RE.search(yaml.safe_dump(value)))


def is_falsy(value) -> bool:
    """actions/runner EvaluationResult.IsFalsy."""
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0 or value != value
    if isinstance(value, str):
        return value == ""
    return False


def is_truthy(value) -> bool:
    return not is_falsy(value)


def abstract_equal(left, right) -> bool:
    """String equality is ordinal-ignore-case; mismatched kinds are not equal."""
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right):
        return left == right
    return False


class ExprError(Exception):
    pass


class Parser:
    def __init__(self, text: str, scope: dict):
        self.text = text
        self.n = len(text)
        self.i = 0
        self.scope = scope

    def parse(self):
        value = self.parse_or()
        self.skip()
        if self.i != self.n:
            raise ExprError(f"trailing {self.text[self.i:]!r} in {self.text!r}")
        return value

    def skip(self):
        while self.i < self.n and self.text[self.i].isspace():
            self.i += 1

    def parse_or(self):
        value = self.parse_and()
        while True:
            self.skip()
            if self.text.startswith("||", self.i):
                self.i += 2
                right = self.parse_and()
                if is_truthy(value):
                    continue
                value = right
            else:
                return value

    def parse_and(self):
        value = self.parse_not()
        while True:
            self.skip()
            if self.text.startswith("&&", self.i):
                self.i += 2
                right = self.parse_not()
                if is_falsy(value):
                    continue
                value = right
            else:
                return value

    def parse_not(self):
        self.skip()
        if self.text.startswith("!", self.i) and not self.text.startswith("!=", self.i):
            self.i += 1
            return is_falsy(self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        value = self.parse_postfix()
        self.skip()
        for op in ("==", "!=", ">=", "<=", ">", "<"):
            if self.text.startswith(op, self.i):
                self.i += len(op)
                right = self.parse_postfix()
                if op == "==":
                    return abstract_equal(value, right)
                if op == "!=":
                    return not abstract_equal(value, right)
                raise ExprError(f"unsupported comparison {op}")
        return value

    def parse_postfix(self):
        value = self.parse_atom()
        while True:
            self.skip()
            if self.i < self.n and self.text[self.i] == ".":
                self.i += 1
                if self.i < self.n and self.text[self.i] == "*":
                    self.i += 1
                    value = ("*", value if isinstance(value, list) else [])
                    continue
                name = self.read_name()
                value = lookup_property(value, name)
                continue
            if self.i < self.n and self.text[self.i] == "(":
                raise ExprError("call must follow a name")
            if self.i < self.n and self.text[self.i] == "[":
                self.i += 1
                index = self.parse_or()
                self.skip()
                if self.i >= self.n or self.text[self.i] != "]":
                    raise ExprError("unclosed index")
                self.i += 1
                value = lookup_property(value, index)
                continue
            return value

    def parse_atom(self):
        self.skip()
        if self.i >= self.n:
            raise ExprError(f"unexpected end in {self.text!r}")
        ch = self.text[self.i]
        if ch == "(":
            self.i += 1
            value = self.parse_or()
            self.skip()
            if self.i >= self.n or self.text[self.i] != ")":
                raise ExprError("unclosed group")
            self.i += 1
            return value
        if ch == "'":
            return self.read_string()
        if ch.isalpha() or ch == "_":
            name = self.read_name()
            self.skip()
            if self.i < self.n and self.text[self.i] == "(":
                self.i += 1
                args = []
                self.skip()
                if self.i < self.n and self.text[self.i] != ")":
                    while True:
                        args.append(self.parse_or())
                        self.skip()
                        if self.i < self.n and self.text[self.i] == ",":
                            self.i += 1
                            continue
                        break
                if self.i >= self.n or self.text[self.i] != ")":
                    raise ExprError("unclosed call")
                self.i += 1
                return call_function(name, args)
            if name == "true":
                return True
            if name == "false":
                return False
            if name == "null":
                return None
            return lookup_name(self.scope, name)
        raise ExprError(f"unexpected {self.text[self.i:]!r}")

    def read_name(self) -> str:
        self.skip()
        start = self.i
        if start >= self.n or not (self.text[start].isalpha() or self.text[start] == "_"):
            raise ExprError(f"expected name in {self.text!r}")
        self.i += 1
        while self.i < self.n and (self.text[self.i].isalnum() or self.text[self.i] in "_-"):
            self.i += 1
        return self.text[start : self.i]

    def read_string(self) -> str:
        self.i += 1
        chars = []
        while self.i < self.n:
            ch = self.text[self.i]
            if ch == "'":
                if self.i + 1 < self.n and self.text[self.i + 1] == "'":
                    chars.append("'")
                    self.i += 2
                    continue
                self.i += 1
                return "".join(chars)
            chars.append(ch)
            self.i += 1
        raise ExprError("unclosed string")


def lookup_name(scope: dict, name: str):
    if name not in scope:
        raise ExprError(f"unknown context {name}")
    return scope[name]


def lookup_property(value, name):
    if isinstance(value, tuple) and value and value[0] == "*":
        return [lookup_property(item, name) for item in value[1]]
    if isinstance(value, _Secrets):
        return SECRET_VALUE
    if isinstance(value, dict):
        return value.get(str(name))
    return None


def call_function(name: str, args: list):
    key = name.casefold()
    if key == "success":
        return True
    if key == "always":
        return True
    if key == "failure":
        return False
    if key == "cancelled":
        return False
    if key == "fromjson":
        if len(args) != 1:
            raise ExprError("fromJSON arity")
        if args[0] in (None, ""):
            return None
        return json.loads(args[0])
    if key == "startswith":
        if len(args) != 2 or not isinstance(args[0], str) or not isinstance(args[1], str):
            return False
        return args[0].casefold().startswith(args[1].casefold())
    if key == "contains":
        if len(args) != 2:
            return False
        if isinstance(args[0], str) and isinstance(args[1], str):
            return args[1].casefold() in args[0].casefold()
        if isinstance(args[0], list):
            return any(abstract_equal(item, args[1]) for item in args[0])
        return False
    raise ExprError(f"unsupported function {name}")


class _Secrets:
    pass


def eval_expr(expr: str, scope: dict):
    return Parser(expr, scope).parse()


def condition_holds(condition, scope: dict) -> bool:
    """Apply WorkflowTemplateConverter.ConvertToIfCondition, then IsTruthy."""
    if condition is None:
        return True
    if isinstance(condition, bool):
        return condition
    text = str(condition).strip()
    wrapped = EXPR_RE.fullmatch(text)
    if wrapped:
        text = wrapped.group(1).strip()
    if text == "":
        return True
    if not STATUS_FN_RE.search(text):
        text = f"success() && ({text})"
    return is_truthy(eval_expr(text, scope))


EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)


def render_template(value, scope: dict):
    if isinstance(value, str):
        if EXPR_RE.fullmatch(value.strip()) is None and "${{" not in value:
            return value

        def replace(match):
            result = eval_expr(match.group(1), scope)
            if result is None:
                return ""
            if isinstance(result, bool):
                return "true" if result else "false"
            return str(result)

        return EXPR_RE.sub(replace, value)
    if isinstance(value, dict):
        return {key: render_template(item, scope) for key, item in value.items()}
    if isinstance(value, list):
        return [render_template(item, scope) for item in value]
    return value


def github_scope(event: dict, steps: dict, needs: dict, inputs: dict) -> dict:
    issue = {
        "number": 1,
        "author_association": event["association"],
        "pull_request": {} if event.get("issue_is_pull") else None,
    }
    pull = {
        "draft": event["draft"],
        "title": "preview",
        "labels": [{"name": name} for name in event.get("labels", [])],
        "head": {
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "ref": "topic",
            "repo": {"fork": event["fork"], "full_name": event["repository"]},
        },
    }
    return {
        "github": {
            "repository": event["repository"],
            "repository_owner": event["repository"].split("/")[0],
            "event_name": event["name"],
            "actor": event["actor"],
            "token": GITHUB_TOKEN,
            "ref": f"refs/heads/{event['ref_name']}",
            "ref_name": event["ref_name"],
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "head_ref": "topic",
            "workflow": "test",
            "event": {
                "number": 1,
                "issue": issue,
            "comment": {
                "body": event["comment"],
                "author_association": event["association"],
            },
            "pull_request": pull,
                "action": event["type"],
            },
        },
        "steps": steps,
        "needs": needs,
        "secrets": _Secrets(),
        "inputs": inputs,
        "env": {},
        "vars": {},
        "matrix": {},
        "runner": {"os": "Linux", "arch": "ARM64"},
        "job": {"status": "success"},
        "strategy": {},
    }


def trigger_accepts(on, event: dict) -> bool:
    if on is None:
        return False
    name = event["name"]
    if isinstance(on, str):
        return on == name
    if isinstance(on, list):
        return name in on
    if not isinstance(on, dict) or name not in on:
        return False
    spec = on[name]
    if not isinstance(spec, dict):
        return True
    types = spec.get("types")
    if isinstance(types, list) and event["type"] not in types:
        return False
    branches = spec.get("branches")
    if isinstance(branches, list):
        if not any(fnmatch_branch(event["ref_name"], pattern) for pattern in branches):
            return False
    return True


def fnmatch_branch(ref_name: str, pattern: str) -> bool:
    # GitHub branch filters use * as a wildcard. A pattern without * is exact.
    if "*" not in pattern and "?" not in pattern:
        return ref_name == pattern
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(regex, ref_name) is not None


def events_for(repository: str):
    common = {
        "repository": repository,
        "actor": "outside-contributor",
        "association": "NONE",
        "comment": "hello",
        "fork": False,
        "draft": False,
        "labels": [],
    }
    specs = [
        ("issue_comment", "created", "main"),
        ("issues", "labeled", "main"),
        ("issues", "unlabeled", "main"),
        ("issues", "opened", "main"),
        ("pull_request", "opened", "main"),
        ("pull_request", "synchronize", "main"),
        ("pull_request_target", "labeled", "main"),
        ("pull_request_target", "opened", "main"),
        ("pull_request_target", "synchronize", "main"),
        ("push", "push", "main"),
        ("push", "push", "release-11.2.3"),
        ("workflow_dispatch", "workflow_dispatch", "main"),
        ("workflow_dispatch", "workflow_dispatch", "release-11.2.3"),
        ("schedule", "schedule", "main"),
        ("workflow_call", "workflow_call", "main"),
        ("workflow_call", "workflow_call", "release-11.2.3"),
    ]
    events = []
    for name, typ, ref_name in specs:
        event = dict(common)
        event.update({"name": name, "type": typ, "ref_name": ref_name})
        events.append(event)
    labeled = dict(common)
    labeled.update({
        "name": "pull_request",
        "type": "opened",
        "ref_name": "main",
        "labels": ["deploy-frontend-preview"],
    })
    events.append(labeled)
    member_comment = dict(common)
    member_comment.update({
        "name": "issue_comment",
        "type": "created",
        "ref_name": "main",
        "association": "MEMBER",
        "comment": "/deploy-to-fs",
        "issue_is_pull": True,
    })
    events.append(member_comment)
    return events


def dispatch_inputs(workflow: dict) -> dict:
    on = workflow.get("on")
    inputs = {}
    if not isinstance(on, dict):
        return inputs
    for key in ("workflow_dispatch", "workflow_call"):
        spec = on.get(key)
        if not isinstance(spec, dict):
            continue
        declared = spec.get("inputs") or {}
        if not isinstance(declared, dict):
            continue
        for name, meta in declared.items():
            if isinstance(meta, dict) and "default" in meta:
                default = meta["default"]
                inputs[name] = "true" if default is True else "false" if default is False else default
            else:
                inputs[name] = "placeholder-input"
    return inputs


def run_shell_step(script: str) -> dict:
    """Run a workflow `run` script after expression rendering.

    Only the repository gate in commands.yml is a pure local comparison. Other
    run steps talk to GitHub or Vault; those outputs stay unset, which is the
    same result as a failing command that does not write GITHUB_OUTPUT.
    """
    if re.search(r"\b(curl|wget|gh|docker|npm|yarn|vault|go)\b", script):
        return {}
    output = tempfile.NamedTemporaryFile(prefix="gha-output-", delete=False)
    output.close()
    env = {"PATH": os.environ.get("PATH", ""), "GITHUB_OUTPUT": output.name, "HOME": os.environ.get("HOME", "/tmp")}
    try:
        completed = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            return {}
        values = {}
        for line in Path(output.name).read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        return values
    finally:
        os.unlink(output.name)


def modelled_step_outputs(step: dict, rendered_with) -> dict | None:
    uses = step.get("uses")
    parsed = parse_uses(uses) if isinstance(uses, str) else None
    if parsed and parsed["path"].endswith("create-github-app-token"):
        return {"token": APP_TOKEN}
    if parsed and parsed["path"].endswith("get-vault-secrets"):
        secrets = {}
        blob = ""
        if isinstance(rendered_with, dict):
            blob = "\n".join(
                str(rendered_with.get(key) or "") for key in ("repo_secrets", "common_secrets")
            )
        for line in blob.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            secrets[key] = VAULT_SECRET
        return {"secrets": json.dumps(secrets)}
    return None


class OIDCServer:
    def __init__(self):
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _OIDCHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/oidc"

    def close(self):
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()


class _OIDCHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # @actions/core 1.6.0 oidc-utils.js reads JSON field `value`.
        body = json.dumps({"value": OIDC_RESPONSE}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def resolve_ref(repo: Path, ref: str) -> str | None:
    """Resolve the uses ref the way a fresh runner uses the download info.

    A 40-hex ref is an object name. Any other ref is the branch the attacker
    just updated. Missing objects are not downloaded.
    """
    if is_full_sha(ref):
        spec = f"{ref}^{{commit}}"
    else:
        spec = f"refs/heads/{ref}"
    completed = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--end-of-options", spec],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def write_attacker_repo(repo: Path, parsed: dict, ref: str):
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    branch = ref if not is_full_sha(ref) else "main"
    git(repo, "init", "-q", "-b", branch)
    root = repo
    if parsed["path"].endswith((".yml", ".yaml")):
        target = root / parsed["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        (root / "capture.js").write_text(CAPTURE_JS)
        target.write_text(
            "name: attacker\n"
            "on:\n"
            "  workflow_call:\n"
            "jobs:\n"
            "  capture:\n"
            "    runs-on: ubuntu-latest\n"
            "    permissions:\n"
            "      id-token: write\n"
            "    steps:\n"
            "      - shell: bash\n"
            "        run: node capture.js \"$CAPTURE_PATH\"\n"
        )
    else:
        action_dir = root / parsed["path"] if parsed["path"] else root
        action_dir.mkdir(parents=True, exist_ok=True)
        (action_dir / "index.js").write_text(CAPTURE_JS)
        (action_dir / "action.yml").write_text(
            "name: attacker\n"
            "runs:\n"
            "  using: node24\n"
            "  main: index.js\n"
        )
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=attacker@example.com", "-c", "user.name=Attacker", "commit", "-q", "-m", "replace action")


def execute_resolved(repo: Path, sha: str, parsed: dict, env: dict, capture: Path) -> dict:
    archive = Path(tempfile.mkdtemp(prefix="gha-action-"))
    try:
        tar = subprocess.run(
            ["git", "-C", str(repo), "archive", sha],
            check=True,
            capture_output=True,
        )
        subprocess.run(["tar", "-x", "-C", str(archive)], input=tar.stdout, check=True)
        run_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "CAPTURE_PATH": str(capture),
        }
        run_env.update(env)
        if parsed["path"].endswith((".yml", ".yaml")):
            workflow_path = archive / parsed["path"]
            called = yaml.safe_load(workflow_path.read_text())
            jobs = called.get("jobs") or {}
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps") or []:
                    if isinstance(step, dict) and step.get("run"):
                        script = render_template(step["run"], {"secrets": _Secrets(), "inputs": {}})
                        subprocess.run(
                            ["bash", "-euo", "pipefail", "-c", script],
                            cwd=archive,
                            env=run_env,
                            check=True,
                            capture_output=True,
                            text=True,
                        )
        else:
            action_dir = archive / parsed["path"] if parsed["path"] else archive
            manifest_path = action_dir / "action.yml"
            if not manifest_path.exists():
                manifest_path = action_dir / "action.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            script = manifest["runs"]["main"]
            subprocess.run(
                ["node", script, str(capture)],
                cwd=action_dir,
                env=run_env,
                check=True,
                capture_output=True,
                text=True,
            )
        if not capture.exists():
            return {}
        return json.loads(capture.read_text())
    finally:
        shutil.rmtree(archive)


def input_env(rendered_with, rendered_env) -> dict:
    """Handler.AddInputsToEnvironment plus the step env mapping."""
    env = {}
    if isinstance(rendered_env, dict):
        for key, value in rendered_env.items():
            env[str(key)] = "" if value is None else str(value)
    if isinstance(rendered_with, dict):
        for key, value in rendered_with.items():
            name = "INPUT_" + str(key).replace(" ", "_").upper()
            env[name] = "" if value is None else str(value)
    return env


def captured_placeholders(payload: dict) -> list[str]:
    found = []
    if not payload:
        return found
    blob = {
        "inputs": payload.get("inputs") or {},
        "oidc": payload.get("oidc") or "",
        "envToken": payload.get("envToken") or "",
    }
    for key, value in blob["inputs"].items():
        if value in PLACEHOLDERS:
            found.append(key)
    if blob["oidc"] in PLACEHOLDERS:
        found.append("oidc")
    if blob["envToken"] in PLACEHOLDERS:
        found.append("LEAKED_TOKEN")
    return found


def job_order(jobs: dict) -> list[str]:
    pending = {name: job for name, job in jobs.items() if isinstance(job, dict)}
    ordered = []
    while pending:
        ready = []
        for name, job in pending.items():
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            if all(need in ordered or need not in jobs for need in needs):
                ready.append(name)
        if not ready:
            raise ExprError(f"cyclic needs among {sorted(pending)}")
        for name in ready:
            ordered.append(name)
            pending.pop(name)
    return ordered


def step_is_candidate(workflow: dict, job: dict, step: dict) -> dict | None:
    parsed = parse_uses(step.get("uses"))
    if not parsed or is_full_sha(parsed["ref"]):
        return None
    if parsed["owner"] in OFFICIAL_OWNERS or parsed["name"] == "grafana/grafana":
        return None
    perms = effective_permissions(workflow, job)
    credential = contains_credential(step.get("with")) or contains_credential(step.get("env"))
    if isinstance(step.get("secrets"), (dict, str)):
        credential = True
    if not credential and not id_token_write(perms):
        return None
    parsed = dict(parsed)
    parsed["credential"] = credential
    parsed["id_token"] = id_token_write(perms)
    return parsed


def find_candidates() -> list[dict]:
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        workflow = load_workflow(path)
        jobs = workflow.get("jobs") or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if job.get("uses"):
                synthetic = {
                    "uses": job.get("uses"),
                    "with": job.get("with"),
                    "env": None,
                    "secrets": job.get("secrets"),
                    "name": f"job {job_name}",
                }
                parsed = step_is_candidate(workflow, job, synthetic)
                if parsed:
                    found.append({"file": path, "workflow": workflow, "job": job_name, "step_name": synthetic["name"], "parsed": parsed, "job_uses": True})
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                parsed = step_is_candidate(workflow, job, step)
                if not parsed:
                    continue
                found.append({
                    "file": path,
                    "workflow": workflow,
                    "job": job_name,
                    "step_name": step.get("name") or f"step {index}",
                    "parsed": parsed,
                    "job_uses": False,
                })
    return found


def reach(candidate: dict, event: dict, oidc: OIDCServer, work: Path):
    """Return the capture payload if this event runs the candidate step."""
    workflow = candidate["workflow"]
    if not trigger_accepts(workflow.get("on"), event):
        return None
    jobs = workflow.get("jobs") or {}
    job_results = {}
    scope_inputs = dispatch_inputs(workflow)
    for job_name in job_order(jobs):
        job = jobs[job_name]
        needs = job.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        if any(job_results.get(need, {}).get("result") != "success" for need in needs):
            job_results[job_name] = {"result": "skipped", "outputs": {}}
            continue
        needs_scope = {
            need: {"result": job_results[need]["result"], "outputs": job_results[need]["outputs"]}
            for need in needs
            if need in job_results
        }
        scope = github_scope(event, {}, needs_scope, scope_inputs)
        if not condition_holds(job.get("if"), scope):
            job_results[job_name] = {"result": "skipped", "outputs": {}}
            continue
        if job_name != candidate["job"]:
            # The candidate's own job is simulated below. Other jobs only need
            # outputs that later conditions read. Run their local shell steps
            # and modelled token steps so those outputs exist.
            outputs = {}
            steps_scope = {}
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                step_scope = github_scope(event, steps_scope, needs_scope, scope_inputs)
                if not condition_holds(step.get("if"), step_scope):
                    continue
                step_id = step.get("id")
                rendered_with = render_template(step.get("with"), step_scope)
                modelled = modelled_step_outputs(step, rendered_with)
                produced = {}
                if modelled is not None:
                    produced = modelled
                elif step.get("run"):
                    script = render_template(step["run"], step_scope)
                    produced = run_shell_step(script)
                if step_id and produced:
                    outputs.update(produced)
                    steps_scope[step_id] = {"outputs": produced, "conclusion": "success"}
            if job.get("uses") and job_name == candidate["job"]:
                pass
            job_results[job_name] = {"result": "success", "outputs": outputs}
            continue

        steps_scope = {}
        steps = []
        if candidate["job_uses"]:
            steps = [{
                "name": candidate["step_name"],
                "uses": job.get("uses"),
                "with": job.get("with"),
                "secrets": job.get("secrets"),
            }]
        else:
            steps = list(job.get("steps") or [])
        ran = False
        payload = {}
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_scope = github_scope(event, steps_scope, needs_scope, scope_inputs)
            if not condition_holds(step.get("if"), step_scope):
                continue
            rendered_with = render_template(step.get("with"), step_scope)
            rendered_env = render_template(step.get("env"), step_scope)
            modelled = modelled_step_outputs(step, rendered_with)
            parsed = parse_uses(step.get("uses")) if step.get("uses") else None
            is_target = (
                parsed
                and parsed["uses"] == candidate["parsed"]["uses"]
                and (step.get("name") or "") == (candidate["step_name"] if not candidate["step_name"].startswith("step ") else step.get("name") or "")
            )
            # Match the candidate by uses string and step name. Generated names
            # use the index, so compare uses plus name when the name was set.
            same_step = parsed and parsed["uses"] == candidate["parsed"]["uses"] and (
                step.get("name") == candidate["step_name"] or candidate["step_name"].startswith("step ")
            )
            if same_step and not ran:
                env = input_env(rendered_with, rendered_env)
                if step.get("secrets") == "inherit" or isinstance(step.get("secrets"), dict):
                    env["LEAKED_TOKEN"] = GITHUB_TOKEN
                if candidate["parsed"]["id_token"]:
                    env["ACTIONS_ID_TOKEN_REQUEST_URL"] = oidc.url
                    env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST
                action_repo = work / "action"
                write_attacker_repo(action_repo, parsed, parsed["ref"])
                sha = resolve_ref(action_repo, parsed["ref"])
                capture = work / "capture.json"
                if capture.exists():
                    capture.unlink()
                if sha is None:
                    payload = {}
                else:
                    payload = execute_resolved(action_repo, sha, parsed, env, capture)
                ran = True
                break
            step_id = step.get("id")
            produced = modelled if modelled is not None else {}
            if modelled is None and step.get("run"):
                produced = run_shell_step(render_template(step["run"], step_scope))
            if step_id and produced:
                steps_scope[step_id] = {"outputs": produced, "conclusion": "success"}
            _ = is_target
        if not ran:
            return None
        return payload
    return None


class UnpinnedActionCredentialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oidc = OIDCServer()
        cls.work = Path(tempfile.mkdtemp(prefix="gha-unpinned-"))
        cls.candidates = find_candidates()

    @classmethod
    def tearDownClass(cls):
        cls.oidc.close()
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_commands_workflow_is_a_candidate(self):
        matches = [
            item for item in self.candidates
            if item["file"].name == "commands.yml" and item["parsed"]["uses"].endswith("commands@main")
        ]
        self.assertTrue(matches, "commands.yml no longer passes a credential to commands@main")

    def test_issue_comment_on_grafana_delivers_credential_to_moving_ref(self):
        self._assert_commands_event_does_not_deliver("issue_comment", "created", "grafana/grafana")

    def test_issue_label_on_grafana_delivers_credential_to_moving_ref(self):
        self._assert_commands_event_does_not_deliver("issues", "labeled", "grafana/grafana")

    def test_issue_unlabel_on_grafana_delivers_credential_to_moving_ref(self):
        self._assert_commands_event_does_not_deliver("issues", "unlabeled", "grafana/grafana")

    def test_issue_comment_on_a_fork_does_not_deliver_credential(self):
        payload = self._commands_payload("issue_comment", "created", "outside/grafana")
        self.assertEqual(captured_placeholders(payload or {}), [])

    def test_pinned_sha_does_not_execute_the_branch_the_attacker_moved(self):
        workflow = load_workflow(WORKFLOWS / "commands.yml")
        job = workflow["jobs"]["main"]
        for step in job["steps"]:
            if isinstance(step, dict) and step.get("uses", "").startswith("grafana/grafana-github-actions/commands@"):
                step["uses"] = "grafana/grafana-github-actions/commands@" + ("ab" * 20)
        candidate = {
            "file": WORKFLOWS / "commands.yml",
            "workflow": workflow,
            "job": "main",
            "step_name": "Run commands",
            "parsed": parse_uses(step["uses"]) | {"credential": True, "id_token": True},
            "job_uses": False,
        }
        event = events_for("grafana/grafana")[0]
        payload = reach(candidate, event, self.oidc, self.work / "pinned")
        self.assertEqual(captured_placeholders(payload or {}), [])

    def test_harness_sees_delivery_when_the_ref_is_the_attacker_commit(self):
        workflow = load_workflow(WORKFLOWS / "commands.yml")
        action_repo = self.work / "known-sha"
        parsed = parse_uses("grafana/grafana-github-actions/commands@main")
        write_attacker_repo(action_repo, parsed, "main")
        sha = git(action_repo, "rev-parse", "HEAD")
        self.assertTrue(is_full_sha(sha))
        for step in workflow["jobs"]["main"]["steps"]:
            if isinstance(step, dict) and str(step.get("uses", "")).startswith("grafana/grafana-github-actions/commands@"):
                step["uses"] = f"grafana/grafana-github-actions/commands@{sha}"
        # The attacker commit is the object named by the SHA, so resolving that
        # SHA must still execute it. Reuse the repo by pointing the simulator at
        # a copy that already contains this object and no extra branch update.
        candidate = {
            "file": WORKFLOWS / "commands.yml",
            "workflow": workflow,
            "job": "main",
            "step_name": "Run commands",
            "parsed": parse_uses(step["uses"]) | {"credential": True, "id_token": True},
            "job_uses": False,
        }
        # reach() rebuilds the action repo, which would not contain this SHA.
        # Resolve and execute against the repo that holds the commit.
        event = next(item for item in events_for("grafana/grafana") if item["name"] == "issue_comment")
        self.assertTrue(trigger_accepts(workflow.get("on"), event))
        payload = self._execute_existing_repo(candidate, event, action_repo)
        self.assertIn("INPUT_TOKEN", captured_placeholders(payload))
        self.assertIn("oidc", captured_placeholders(payload))

    def _assert_commands_event_does_not_deliver(self, name: str, typ: str, repository: str):
        payload = self._commands_payload(name, typ, repository)
        self.assertIsNotNone(payload, f"{name}/{typ} did not run the commands step")
        self.assertEqual(captured_placeholders(payload), [])

    def _commands_payload(self, name: str, typ: str, repository: str):
        candidate = next(
            item for item in self.candidates
            if item["file"].name == "commands.yml" and item["parsed"]["path"] == "commands"
        )
        event = next(item for item in events_for(repository) if item["name"] == name and item["type"] == typ)
        return reach(candidate, event, self.oidc, self.work / "commands")

    def _execute_existing_repo(self, candidate, event, action_repo: Path):
        workflow = candidate["workflow"]
        jobs = workflow["jobs"]
        # Run the config job's shell so the repository gate is the real script.
        config = jobs["config"]
        scope = github_scope(event, {}, {}, {})
        produced = {}
        for step in config["steps"]:
            script = render_template(step["run"], scope)
            produced = run_shell_step(script)
        needs_scope = {"config": {"result": "success", "outputs": produced}}
        scope = github_scope(event, {}, needs_scope, {})
        if not condition_holds(jobs["main"].get("if"), scope):
            return {}
        steps_scope = {}
        for step in jobs["main"]["steps"]:
            step_scope = github_scope(event, steps_scope, needs_scope, {})
            rendered_with = render_template(step.get("with"), step_scope)
            modelled = modelled_step_outputs(step, rendered_with)
            if step.get("id") and modelled:
                steps_scope[step["id"]] = {"outputs": modelled}
                continue
            parsed = parse_uses(step.get("uses"))
            if parsed and is_full_sha(parsed["ref"]):
                env = input_env(rendered_with, None)
                env["ACTIONS_ID_TOKEN_REQUEST_URL"] = self.oidc.url
                env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST
                sha = resolve_ref(action_repo, parsed["ref"])
                capture = self.work / "known-capture.json"
                if capture.exists():
                    capture.unlink()
                if sha is None:
                    return {}
                return execute_resolved(action_repo, sha, parsed, env, capture)
        return {}


if __name__ == "__main__":
    unittest.main()
