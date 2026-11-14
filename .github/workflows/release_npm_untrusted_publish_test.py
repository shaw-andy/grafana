#!/usr/bin/env python3
"""Failing spec for the NPM release workflow trusting the dispatched ref.

These tests execute .github/workflows/release-npm.yml the way GitHub Actions
runs a workflow_dispatch (and the same job on workflow_call): checkout, the
commit check, then the publish script in the job that holds id-token: write.

They must fail while that job runs scripts from a caller-chosen commit, and
pass once the commit check and the publish script run only from a pinned
trusted ref, a commit that is not an ancestor of main or a creation-restricted
release branch (release-*.*.*) is rejected before any of its files run, and
the job that can request an OIDC token does not build or publish from that
commit.

Run:

    python3 .github/workflows/release_npm_untrusted_publish_test.py
"""

from __future__ import annotations

import base64
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_REL = Path(".github/workflows/release-npm.yml")

# Deployment branch rules on the grafana/grafana npm-publish environment.
# Patterns are matched the way Ruby File.fnmatch does with FNM_PATHNAME
# (* does not match '/'), against the short branch name. `main` only matches
# a workflow_dispatch ref of main that way; `release-*` also matches a branch
# the creation ruleset does not block (that ruleset is release-*.*.*).
NPM_PUBLISH_BRANCH_RULES = ("main", "release-*")
TRUSTED_RELEASE_BRANCH = re.compile(r"^release-[^/]*\.[^/]*\.[^/]*$")

OIDC_REQUEST_TOKEN = "placeholder-actions-id-token-request-token"
EXCHANGED_PUBLISH_TOKEN = "placeholder-exchanged-npm-token"
REGISTRY_ARGUMENT = "https://registry.npmjs.org/"


class NoBoolLoader(yaml.SafeLoader):
    pass


NoBoolLoader.yaml_implicit_resolvers = {
    key: [item for item in value if item[0] != "tag:yaml.org,2002:bool"]
    for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def fnmatch_pathname(pattern: str, name: str) -> bool:
    """Ruby File.fnmatch(pattern, name, File::FNM_PATHNAME)."""

    def rec(i: int, j: int) -> bool:
        if i == len(pattern):
            return j == len(name)
        if pattern[i] == "*":
            k = j
            while True:
                if rec(i + 1, k):
                    return True
                if k >= len(name) or name[k] == "/":
                    return False
                k += 1
        if j >= len(name):
            return False
        if pattern[i] == "?":
            if name[j] == "/":
                return False
            return rec(i + 1, j + 1)
        if pattern[i] != name[j]:
            return False
        return rec(i + 1, j + 1)

    return rec(0, 0)


def branch_allowed_by_npm_environment(ref_name: str) -> bool:
    return any(fnmatch_pathname(rule, ref_name) for rule in NPM_PUBLISH_BRANCH_RULES)


def trusted_release_ref(ref_name: str) -> bool:
    return ref_name == "main" or TRUSTED_RELEASE_BRANCH.match(ref_name) is not None


class _ServerState:
    def __init__(self) -> None:
        self.claims = {}
        self.publishes = []
        self.exchanges = []
        self.lock = threading.Lock()


SERVER_STATE = _ServerState()
HTTP_SERVER = None
HTTP_PORT = None


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/token":
            self._json(404, {})
            return
        query = urllib.parse.parse_qs(parsed.query)
        audience = (query.get("audience") or [""])[0]
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {OIDC_REQUEST_TOKEN}":
            self._json(401, {})
            return
        if not audience.startswith("npm:"):
            self._json(400, {"message": "missing npm audience"})
            return
        with SERVER_STATE.lock:
            claims = dict(SERVER_STATE.claims)
        payload = base64.b64encode(json.dumps(claims).encode()).decode()
        token = f"eyJhbGciOiJub25lIn0.{payload}.placeholder"
        self._json(200, {"value": token})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        prefix = "/-/npm/v1/oidc/token/exchange/package/"
        if not self.path.startswith(prefix):
            self._json(404, {})
            return
        escaped = self.path[len(prefix):]
        auth = self.headers.get("Authorization", "")
        id_token = auth.removeprefix("Bearer ").strip()
        parts = id_token.split(".")
        if len(parts) < 2:
            self._json(401, {"message": "missing id token"})
            return
        claims = json.loads(base64.b64decode(parts[1]))
        workflow_ref = claims.get("workflow_ref", "")
        filename = workflow_ref.split("@", 1)[0].rsplit("/", 1)[-1]
        accepted = (
            claims.get("repository") == "grafana/grafana"
            and filename == "release-npm.yml"
            and claims.get("environment") == "npm-publish"
        )
        with SERVER_STATE.lock:
            SERVER_STATE.exchanges.append(
                {"escaped_package": escaped, "accepted": accepted, "ref": claims.get("ref"), "filename": filename}
            )
        if not accepted:
            self._json(403, {"message": "trusted publisher mismatch"})
            return
        self._json(200, {"token": EXCHANGED_PUBLISH_TOKEN})

    def do_PUT(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {EXCHANGED_PUBLISH_TOKEN}":
            self._json(401, {})
            return
        with SERVER_STATE.lock:
            SERVER_STATE.publishes.append({"path": self.path, "bytes": len(body)})
        self._json(200, {"ok": True})


def _ensure_server() -> None:
    global HTTP_SERVER, HTTP_PORT
    if HTTP_SERVER is not None:
        return
    HTTP_SERVER = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    HTTP_PORT = HTTP_SERVER.server_address[1]
    thread = threading.Thread(target=HTTP_SERVER.serve_forever, daemon=True)
    thread.start()


def _run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, text=True, capture_output=True)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=repo, check=check)


class WorkflowRun:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.attack_log = root / "attack.log"
        self.workspace = root / "workspace"
        self.origin = root / "origin.git"
        self.bin_dir = root / "bin"
        self.publishes_before = 0

    def read_attack_log(self) -> str:
        if not self.attack_log.exists():
            return ""
        return self.attack_log.read_text()


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)


def _package_tarball(name: str, version: str) -> bytes:
    manifest = json.dumps({"name": name, "version": version}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(manifest)
        archive.addfile(info, io.BytesIO(manifest))
    return buf.getvalue()


def _init_origin(run: WorkflowRun) -> None:
    _run(["git", "init", "--bare", "-q", str(run.origin)])
    _git(run.origin, "config", "uploadpack.allowReachableSHA1InWant", "true")
    _git(run.origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    seed = run.root / "seed"
    _run(["git", "init", "-q", "-b", "main", str(seed)])
    _git(seed, "config", "user.email", "test@example.com")
    _git(seed, "config", "user.name", "NPM Release Test")
    files = {
        WORKFLOW_REL: (REPO_ROOT / WORKFLOW_REL).read_text(),
        Path(".github/workflows/scripts/validate-commit-in-head.sh"): (
            REPO_ROOT / ".github/workflows/scripts/validate-commit-in-head.sh"
        ).read_text(),
        Path(".github/workflows/scripts/determine-npm-tag.sh"): (
            REPO_ROOT / ".github/workflows/scripts/determine-npm-tag.sh"
        ).read_text(),
        Path(".github/workflows/scripts/detect-e2e-selectors-change.sh"): "#!/bin/bash\necho false\n",
        Path("scripts/publish-npm-packages.sh"): (REPO_ROOT / "scripts/publish-npm-packages.sh").read_text(),
        Path("scripts/validate-npm-packages.sh"): (REPO_ROOT / "scripts/validate-npm-packages.sh").read_text(),
        Path("package.json"): json.dumps(
            {
                "name": "grafana-fixture",
                "version": "0.0.0",
                "scripts": {
                    "packages:typecheck": "true",
                    "packages:build": "true",
                    "packages:pack": "true",
                },
            }
        ),
    }
    for rel, content in files.items():
        _write_executable(seed / rel, content) if rel.suffix == ".sh" else (seed / rel).parent.mkdir(parents=True, exist_ok=True) or (seed / rel).write_text(content)
    _git(seed, "add", ".")
    _git(seed, "commit", "-q", "-m", "trusted main")
    _git(seed, "remote", "add", "origin", str(run.origin))
    _git(seed, "push", "-q", "origin", "main")
    run.seed = seed
    run.main_sha = _git(seed, "rev-parse", "HEAD").stdout.strip()


def _commit_branch(run: WorkflowRun, branch: str, files: dict[str, str], message: str) -> str:
    _git(run.seed, "checkout", "-q", "-B", branch, "main")
    for rel, content in files.items():
        path = run.seed / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if path.suffix == ".sh":
            path.chmod(0o755)
    _git(run.seed, "add", ".")
    _git(run.seed, "commit", "-q", "-m", message)
    _git(run.seed, "push", "-q", "-u", "origin", branch)
    return _git(run.seed, "rev-parse", "HEAD").stdout.strip()


def _marker(run: WorkflowRun, label: str) -> str:
    # The path is outside the runner workspace. checkout's git clean cannot erase it.
    return (
        "#!/bin/bash\n"
        f"printf '%s\\n' {label} >> {run.attack_log}\n"
    )


def _attacker_package_json(run: WorkflowRun) -> str:
    log = str(run.attack_log)
    tarball = _package_tarball("@grafana/pwned", "9.9.9")
    # The build script plants the tarball the real publish script would ship.
    packed = run.root / "pwned.tgz"
    packed.write_bytes(tarball)
    return json.dumps(
        {
            "name": "grafana-fixture",
            "version": "0.0.0",
            "scripts": {
                "packages:typecheck": f"printf '%s\\n' typecheck >> {log}",
                "packages:build": f"printf '%s\\n' build >> {log}",
                "packages:pack": (
                    f"printf '%s\\n' pack >> {log}; mkdir -p npm-artifacts; "
                    f"cp {packed} npm-artifacts/grafana-pwned-9.9.9.tgz"
                ),
            },
        }
    )


def _attacker_publish_script(run: WorkflowRun) -> str:
    log = str(run.attack_log)
    return textwrap.dedent(
        f"""\
        #!/bin/bash
        printf '%s\\n' publish-script >> {log}
        mkdir -p npm-artifacts
        cp {run.root / "pwned.tgz"} npm-artifacts/grafana-pwned-9.9.9.tgz
        npm publish npm-artifacts/grafana-pwned-9.9.9.tgz --tag latest --registry {REGISTRY_ARGUMENT}
        """
    )


def _attacker_files(run: WorkflowRun, *, replace_check: bool, replace_publish: bool, replace_validator: bool, nightly_detect: bool) -> dict[str, str]:
    files = {"package.json": _attacker_package_json(run)}
    _package_tarball("@grafana/pwned", "9.9.9")
    (run.root / "pwned.tgz").write_bytes(_package_tarball("@grafana/pwned", "9.9.9"))
    if replace_check:
        files[".github/workflows/scripts/validate-commit-in-head.sh"] = _marker(run, "commit-check") + "exit 0\n"
    if replace_publish:
        files["scripts/publish-npm-packages.sh"] = _attacker_publish_script(run)
    if replace_validator:
        files["scripts/validate-npm-packages.sh"] = _marker(run, "package-validator") + "exit 0\n"
    if nightly_detect:
        files[".github/workflows/scripts/detect-e2e-selectors-change.sh"] = _marker(run, "nightly-detect") + "echo true\n"
    return files


class ExprError(Exception):
    pass


class _Parser:
    def __init__(self, text: str, scope: dict) -> None:
        self.text = text.strip()
        self.n = len(self.text)
        self.i = 0
        self.scope = scope

    def parse(self):
        value = self._or()
        self._skip()
        if self.i != self.n:
            raise ExprError(f"trailing input in {self.text!r}")
        return value

    def _skip(self) -> None:
        while self.i < self.n and self.text[self.i].isspace():
            self.i += 1

    def _or(self):
        left = self._and()
        while True:
            self._skip()
            if self.text.startswith("||", self.i):
                self.i += 2
                right = self._and()
                left = bool(left) or bool(right)
            else:
                return left

    def _and(self):
        left = self._cmp()
        while True:
            self._skip()
            if self.text.startswith("&&", self.i):
                self.i += 2
                right = self._cmp()
                left = bool(left) and bool(right)
            else:
                return left

    def _cmp(self):
        self._skip()
        if self.text.startswith("!", self.i) and not self.text.startswith("!=", self.i):
            self.i += 1
            return not bool(self._cmp())
        left = self._atom()
        self._skip()
        for op in ("==", "!="):
            if self.text.startswith(op, self.i):
                self.i += 2
                right = self._atom()
                return (str(left) == str(right)) if op == "==" else (str(left) != str(right))
        return left

    def _atom(self):
        self._skip()
        if self.i >= self.n:
            raise ExprError("unexpected end")
        if self.text[self.i] == "(":
            self.i += 1
            value = self._or()
            self._skip()
            if self.i >= self.n or self.text[self.i] != ")":
                raise ExprError("missing )")
            self.i += 1
            return value
        if self.text[self.i] in "'\"":
            quote = self.text[self.i]
            self.i += 1
            start = self.i
            while self.i < self.n and self.text[self.i] != quote:
                self.i += 1
            value = self.text[start:self.i]
            self.i += 1
            return value
        start = self.i
        while self.i < self.n and self.text[self.i] not in " \t()!&|=<>":
            self.i += 1
        word = self.text[start:self.i]
        if word == "true":
            return True
        if word == "false":
            return False
        if word in self.scope:
            return self.scope[word]
        if word.startswith("inputs.") or word.startswith("steps.") or word.startswith("github."):
            return self.scope.get(word, "")
        raise ExprError(f"unknown token {word!r} in {self.text!r}")


def eval_expr(expr: str, scope: dict):
    text = expr.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return _Parser(text, scope).parse()


def render(value: str, scope: dict) -> str:
    def repl(match: re.Match) -> str:
        return str(eval_expr(match.group(1), scope))

    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", repl, value)


def _scope(inputs: dict, outputs: dict, github: dict) -> dict:
    scope = {}
    for key, value in inputs.items():
        scope[f"inputs.{key}"] = value
    for step_id, step_outputs in outputs.items():
        for key, value in step_outputs.items():
            scope[f"steps.{step_id}.outputs.{key}"] = value
    for key, value in github.items():
        scope[f"github.{key}"] = value
    return scope


def _install_stubs(run: WorkflowRun) -> None:
    run.bin_dir.mkdir(parents=True, exist_ok=True)
    test_file = Path(__file__).resolve()
    npm = run.bin_dir / "npm"
    npm.write_text(
        "#!/bin/sh\n"
        f'NPM_PUBLISH_STUB=1 PYTHONPATH= NPM_HTTP_PORT={HTTP_PORT} '
        f'exec python3 {test_file} "$@"\n'
    )
    npm.chmod(0o755)
    yarn = run.bin_dir / "yarn"
    yarn.write_text(
        "#!/bin/sh\n"
        f"YARN_STUB=1 exec python3 {test_file} \"$@\"\n"
    )
    yarn.chmod(0o755)
    tree = run.bin_dir / "tree"
    tree.write_text("#!/bin/sh\nexit 0\n")
    tree.chmod(0o755)


def _checkout(run: WorkflowRun, ref_input: str, fetch_depth: int, github_ref: str, github_sha: str) -> None:
    """actions/checkout v5 input resolution and git checkout, for this repo."""
    ref_input = ref_input.strip()
    if not ref_input:
        ref = github_ref
        commit = github_sha
    elif re.fullmatch(r"[0-9a-fA-F]{40}", ref_input):
        ref = ""
        commit = ref_input
    elif ref_input.startswith("refs/heads/"):
        ref = ref_input
        commit = ""
    else:
        ref = f"refs/heads/{ref_input}"
        commit = ""

    workspace = run.workspace
    if not (workspace / ".git").exists():
        workspace.mkdir(parents=True, exist_ok=True)
        _git(workspace, "init", "-q")
        _git(workspace, "remote", "add", "origin", str(run.origin))
    else:
        _git(workspace, "clean", "-ffdx")
        _git(workspace, "reset", "--hard")

    depth_args = ["--depth", str(fetch_depth)] if fetch_depth > 0 else []
    if commit and ref.startswith("refs/heads/"):
        branch = ref[len("refs/heads/"):]
        refspec = f"+{commit}:refs/remotes/origin/{branch}"
    elif commit and not ref:
        refspec = commit
        branch = ""
    elif ref.startswith("refs/heads/"):
        branch = ref[len("refs/heads/"):]
        refspec = f"+{ref}:refs/remotes/origin/{branch}"
    else:
        raise AssertionError(f"unsupported checkout ref {ref!r} commit {commit!r}")

    _run(["git", "fetch", "-q", *depth_args, "origin", refspec], cwd=workspace)
    if not ref:
        _git(workspace, "checkout", "--force", commit)
    else:
        _git(workspace, "checkout", "--force", "-B", branch, f"refs/remotes/origin/{branch}")


def _parse_outputs(path: Path) -> dict:
    outputs = {}
    if not path.exists():
        return outputs
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            outputs[key] = value
    return outputs


def execute_workflow(run: WorkflowRun, *, ref_name: str, inputs: dict, event_name: str) -> dict:
    _ensure_server()
    _install_stubs(run)
    github_ref = f"refs/heads/{ref_name}"
    github_sha = _git(run.seed, "rev-parse", ref_name).stdout.strip()
    workflow_text = _git(run.seed, "show", f"{github_sha}:{WORKFLOW_REL.as_posix()}").stdout
    workflow = yaml.load(workflow_text, Loader=NoBoolLoader)
    job = workflow["jobs"]["publish"]
    result = {"job_ran": False, "steps": [], "stopped": None}
    if not branch_allowed_by_npm_environment(ref_name):
        result["stopped"] = "environment-branch-policy"
        return result
    github = {"ref": github_ref, "sha": github_sha, "ref_name": ref_name, "repository": "grafana/grafana"}
    scope = _scope(inputs, {}, github)
    job_if = job.get("if")
    if job_if is not None and not bool(eval_expr(str(job_if), scope)):
        result["stopped"] = "job-if"
        return result
    result["job_ran"] = True
    # The runner creates GITHUB_WORKSPACE before the first step. The Info step
    # runs before actions/checkout.
    run.workspace.mkdir(parents=True, exist_ok=True)
    permissions = job.get("permissions") or {}
    id_token_write = permissions.get("id-token") == "write"
    step_outputs: dict[str, dict] = {}
    env_base = os.environ.copy()
    env_base["PATH"] = f"{run.bin_dir}{os.pathsep}{env_base.get('PATH', '')}"
    env_base["GITHUB_ACTIONS"] = "true"
    env_base["CI"] = "true"
    env_base["GITHUB_REF"] = github_ref
    env_base["GITHUB_SHA"] = github_sha
    env_base["GITHUB_REF_NAME"] = ref_name
    env_base["GITHUB_REPOSITORY"] = "grafana/grafana"
    env_base["GITHUB_WORKSPACE"] = str(run.workspace)
    if id_token_write:
        env_base["ACTIONS_ID_TOKEN_REQUEST_URL"] = f"http://127.0.0.1:{HTTP_PORT}/token"
        env_base["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST_TOKEN
        with SERVER_STATE.lock:
            workflow_file = "release-npm.yml" if event_name == "workflow_dispatch" else "caller.yml"
            ref = github_ref
            SERVER_STATE.claims = {
                "repository": "grafana/grafana",
                "repository_owner": "grafana",
                "workflow_ref": f"grafana/grafana/.github/workflows/{workflow_file}@{ref}",
                "environment": str(job.get("environment") or ""),
                "ref": ref,
                "repository_visibility": "public",
                "event_name": event_name,
            }
    for step in job["steps"]:
        scope = _scope(inputs, step_outputs, github)
        step_if = step.get("if")
        if step_if is not None and not bool(eval_expr(str(step_if), scope)):
            result["steps"].append({"name": step.get("name"), "skipped": True})
            continue
        name = step.get("name")
        if "uses" in step:
            uses = str(step["uses"])
            if uses.startswith("actions/checkout@"):
                with_block = step.get("with") or {}
                ref_value = render(str(with_block["ref"]), scope) if "ref" in with_block else ""
                fetch_depth = int(with_block.get("fetch-depth") or 1)
                _checkout(run, ref_value, fetch_depth, github_ref, github_sha)
                result["steps"].append({"name": name, "checkout": _git(run.workspace, "rev-parse", "HEAD").stdout.strip()})
            else:
                result["steps"].append({"name": name, "uses": uses})
            continue
        script = step.get("run")
        if script is None:
            continue
        output_file = run.root / "github_output.txt"
        output_file.write_text("")
        step_env = env_base.copy()
        for key, value in (step.get("env") or {}).items():
            step_env[str(key)] = render(str(value), scope)
        step_env["GITHUB_OUTPUT"] = str(output_file)
        script_path = run.root / "step.sh"
        script_path.write_text(str(script) if str(script).endswith("\n") else str(script) + "\n")
        completed = _run(["bash", "-e", str(script_path)], cwd=run.workspace, env=step_env, check=False)
        result["steps"].append({"name": name, "exit": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr})
        if completed.returncode != 0:
            result["stopped"] = name
            return result
        if step.get("id"):
            step_outputs[step["id"]] = _parse_outputs(output_file)
    return result


def npm_stub_main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--version"]:
        print("11.21.2")
        return 0
    if args[:1] == ["install"]:
        return 0
    if args[:1] == ["view"]:
        print("1.0.0")
        return 0
    if not args or args[0] != "publish":
        print(f"npm stub: unsupported command {args}", flush=True)
        return 1
    tarball = None
    registry = REGISTRY_ARGUMENT
    i = 1
    while i < len(args):
        if args[i] == "--tag":
            i += 2
            continue
        if args[i] == "--registry":
            registry = args[i + 1]
            i += 2
            continue
        if args[i].startswith("-"):
            print(f"npm stub: unsupported flag {args[i]}", flush=True)
            return 1
        tarball = args[i]
        i += 1
    if tarball is None:
        return 1
    import tarfile as _tarfile

    with _tarfile.open(tarball, "r:gz") as archive:
        manifest = json.loads(archive.extractfile("package/package.json").read())
    package_name = manifest["name"]
    escaped = package_name.replace("/", "%2f", 1)
    if os.environ.get("CI") == "false" or not os.environ.get("GITHUB_ACTIONS"):
        print("ENEEDAUTH", flush=True)
        return 1
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not request_token:
        print("ENEEDAUTH", flush=True)
        return 1
    audience = "npm:" + urllib.parse.urlparse(registry).hostname
    token_url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode({"audience": audience})
    request = urllib.request.Request(token_url, headers={"Accept": "application/json", "Authorization": f"Bearer {request_token}"})
    with urllib.request.urlopen(request) as response:
        id_token = json.load(response)["value"]
    exchange = urllib.parse.urlparse(registry)
    exchange_url = f"http://127.0.0.1:{os.environ['NPM_HTTP_PORT']}/-/npm/v1/oidc/token/exchange/package/{escaped}"
    # Host in the registry URL is still the registry the workflow named. The
    # connection is local so the test does not contact the public registry.
    assert exchange.hostname == "registry.npmjs.org"
    post = urllib.request.Request(
        exchange_url,
        data=b"",
        method="POST",
        headers={"Authorization": f"Bearer {id_token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(post) as response:
            exchanged = json.load(response)["token"]
    except urllib.error.HTTPError:
        print("ENEEDAUTH", flush=True)
        return 1
    put = urllib.request.Request(
        f"http://127.0.0.1:{os.environ['NPM_HTTP_PORT']}/{escaped}",
        data=Path(tarball).read_bytes(),
        method="PUT",
        headers={"Authorization": f"Bearer {exchanged}"},
    )
    with urllib.request.urlopen(put) as response:
        response.read()
    return 0


def yarn_stub_main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["run"] and len(args) >= 2:
        manifest = json.loads(Path("package.json").read_text())
        script = manifest.get("scripts", {}).get(args[1])
        if script is None:
            print(f"missing script {args[1]}", flush=True)
            return 1
        completed = subprocess.run(["bash", "-e", "-c", script], check=False)
        return completed.returncode
    if args[:1] == ["lerna"]:
        return 0
    if args[:1] in (["attw"], ["publint"]):
        print("refusing to pretend the real package checker accepted this tarball", flush=True)
        return 1
    print(f"yarn stub: unsupported command {args}", flush=True)
    return 1


class ReleaseNpmUntrustedPublishTest(unittest.TestCase):
    def setUp(self) -> None:
        _ensure_server()
        self._tmpdir = tempfile.TemporaryDirectory()
        self.run = WorkflowRun(Path(self._tmpdir.name))
        _init_origin(self.run)
        with SERVER_STATE.lock:
            SERVER_STATE.publishes.clear()
            SERVER_STATE.exchanges.clear()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _dispatch(self, ref_name: str, version_type: str, commit: str, event_name: str = "workflow_dispatch") -> dict:
        version = "9.9.9" if version_type == "stable" else "9.9.9-123456"
        return execute_workflow(
            self.run,
            ref_name=ref_name,
            event_name=event_name,
            inputs={
                "grafana_commit": commit,
                "version": version,
                "build_id": "1000",
                "version_type": version_type,
            },
        )

    def _assert_attacker_had_no_effect(self, result: dict) -> None:
        log = self.run.read_attack_log()
        with SERVER_STATE.lock:
            publishes = list(SERVER_STATE.publishes)
            exchanges = list(SERVER_STATE.exchanges)
        self.assertEqual(
            ("", []),
            (log, publishes),
            "untrusted commit ran in the npm-publish job or reached the registry\n"
            f"log={log!r}\npublishes={publishes}\nexchanges={exchanges}\nresult={result}",
        )

    def test_branch_pattern_matches_unprotected_release_name(self) -> None:
        self.assertTrue(fnmatch_pathname("release-*", "release-pwn"))
        self.assertTrue(fnmatch_pathname("main", "main"))
        self.assertFalse(fnmatch_pathname("release-*.*.*", "release-pwn"))
        self.assertTrue(fnmatch_pathname("release-*.*.*", "release-13.0.0"))
        self.assertFalse(trusted_release_ref("release-pwn"))
        self.assertTrue(trusted_release_ref("release-13.0.0"))

    def test_dispatch_on_main_rejects_commit_that_is_not_on_main(self) -> None:
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=True, replace_publish=True, replace_validator=True, nightly_detect=False),
            "unmerged",
        )
        result = self._dispatch("main", "stable", attacker)
        self._assert_attacker_had_no_effect(result)
        self.assertEqual("Verify commit is in workflow HEAD", result["stopped"])

    def test_release_wildcard_branch_runs_replaced_check_then_publish(self) -> None:
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=True, replace_publish=True, replace_validator=True, nightly_detect=False),
            "replaced check and publish",
        )
        result = self._dispatch("release-pwn", "stable", attacker)
        self._assert_attacker_had_no_effect(result)

    def test_real_head_check_still_runs_publish_script_from_same_commit(self) -> None:
        # The shipped ancestor check passes because the dispatched branch HEAD is
        # the chosen commit. The publish step then checks that same commit out
        # again and runs whatever publish script is there.
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=False, replace_publish=True, replace_validator=True, nightly_detect=False),
            "real check, replaced publish",
        )
        result = self._dispatch("release-pwn", "stable", attacker)
        self._assert_attacker_had_no_effect(result)
        self.assertNotEqual(attacker, self.run.main_sha)

    def test_real_publish_script_ships_tarball_built_from_unmerged_commit(self) -> None:
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=False, replace_publish=False, replace_validator=True, nightly_detect=False),
            "real publish script, attacker tarball",
        )
        result = self._dispatch("release-pwn", "stable", attacker)
        self._assert_attacker_had_no_effect(result)

    def test_nightly_dispatch_on_release_wildcard_runs_attacker_scripts(self) -> None:
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=False, replace_publish=True, replace_validator=True, nightly_detect=True),
            "nightly",
        )
        result = self._dispatch("release-pwn", "nightly", attacker)
        self._assert_attacker_had_no_effect(result)

    def test_feature_branch_is_stopped_by_environment_before_scripts(self) -> None:
        attacker = _commit_branch(
            self.run,
            "feature-evil",
            _attacker_files(self.run, replace_check=True, replace_publish=True, replace_validator=True, nightly_detect=False),
            "feature",
        )
        result = self._dispatch("feature-evil", "stable", attacker)
        self.assertEqual("environment-branch-policy", result["stopped"])
        self._assert_attacker_had_no_effect(result)

    def test_workflow_call_on_release_wildcard_uses_caller_checkout(self) -> None:
        attacker = _commit_branch(
            self.run,
            "release-pwn",
            _attacker_files(self.run, replace_check=True, replace_publish=True, replace_validator=True, nightly_detect=False),
            "workflow_call",
        )
        result = self._dispatch("release-pwn", "stable", attacker, event_name="workflow_call")
        self._assert_attacker_had_no_effect(result)


if os.environ.get("NPM_PUBLISH_STUB") == "1":
    raise SystemExit(npm_stub_main())

if os.environ.get("YARN_STUB") == "1":
    raise SystemExit(yarn_stub_main())


if __name__ == "__main__":
    unittest.main(verbosity=2)
