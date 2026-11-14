#!/usr/bin/env python3
"""Security spec for Deploy Storybook.

Run from the repository root:

    python3 .github/workflows/deploy_storybook_untrusted_ref_test.py

These tests fail while a caller-chosen ref is checked out in the job that can
mint the production storybook OIDC token and publish gs://grafana-storybook.
They pass once that job checks out only the default branch or a release tag,
the Storybook build runs in a separate job that cannot request an OIDC token,
and only the artifact from that build is published.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_WORKFLOW = REPO_ROOT / ".github/workflows/deploy-storybook.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github/workflows/github-release.yml"

PROD_BUCKET = "grafana-storybook"
PROD_SA = "github-gf-storybook-deploy@grafanalabs-workload-identity.iam.gserviceaccount.com"
# Obvious placeholder. Not a credential.
OIDC_REQUEST_TOKEN = "placeholder-oidc-request-token"
OIDC_REQUEST_URL = "https://oidc.example.invalid/token?placeholder=1"
PREEXISTING = b"preexisting-storybook"
TRUSTED_MARKER = b"trusted-storybook"
ATTACKER_MARKER = b"attacker-storybook"
WIF_PROVIDER = (
    "projects/304398677251/locations/global/workloadIdentityPools/github/providers/github-provider"
)


def load_workflow(path: Path) -> dict:
    data = yaml.safe_load(path.read_text())
    # PyYAML 6.0.1 parses the bare key `on` as boolean true.
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def _is_nan(value: float) -> bool:
    return value != value


def _coerce_number(value):
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        if value == "":
            return 0.0
        try:
            return float(json.loads(value))
        except (json.JSONDecodeError, TypeError):
            return float("nan")
    return float("nan")


def loose_equal(left, right) -> bool:
    """GitHub Actions loose equality. Strings that share a type ignore case."""
    if isinstance(left, str) and isinstance(right, str):
        return left.lower() == right.lower()
    if type(left) is type(right) and not isinstance(left, (dict, list)):
        return left == right
    left_num = _coerce_number(left)
    right_num = _coerce_number(right)
    if _is_nan(left_num) or _is_nan(right_num):
        return False
    return left_num == right_num


class Expr:
    def __init__(self, text: str):
        self.text = text.strip()
        if self.text.startswith("${{") and self.text.endswith("}}"):
            self.text = self.text[3:-2].strip()
        self.tokens = self._lex(self.text)
        self.pos = 0

    def eval(self, ctx: dict):
        if not self.text:
            return None
        self.pos = 0
        value = self._or(ctx)
        if self.pos != len(self.tokens):
            raise AssertionError(f"unused expression tokens in {self.text!r}: {self.tokens[self.pos:]}")
        return value

    def _lex(self, text: str) -> list:
        tokens = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch.isspace():
                i += 1
                continue
            if text.startswith("==", i) or text.startswith("!=", i) or text.startswith("&&", i) or text.startswith("||", i):
                tokens.append(text[i : i + 2])
                i += 2
                continue
            if ch in "!()":
                tokens.append(ch)
                i += 1
                continue
            if ch == "'":
                i += 1
                buf = []
                while i < len(text):
                    if text[i] == "'" and i + 1 < len(text) and text[i + 1] == "'":
                        buf.append("'")
                        i += 2
                        continue
                    if text[i] == "'":
                        i += 1
                        break
                    buf.append(text[i])
                    i += 1
                tokens.append(("str", "".join(buf)))
                continue
            if ch == "." or ch.isalnum() or ch in "_-":
                start = i
                i += 1
                while i < len(text) and (text[i].isalnum() or text[i] in "_.-"):
                    # `.` separates properties; keep it so the parser can split.
                    i += 1
                tokens.append(("id", text[start:i]))
                continue
            raise AssertionError(f"cannot lex {text!r} at {text[i:]!r}")
        return tokens

    def _peek(self):
        if self.pos >= len(self.tokens):
            return None
        return self.tokens[self.pos]

    def _or(self, ctx):
        value = self._and(ctx)
        while self._peek() == "||":
            self.pos += 1
            right = self._and(ctx)
            value = value or right
        return value

    def _and(self, ctx):
        value = self._cmp(ctx)
        while self._peek() == "&&":
            self.pos += 1
            if not value:
                self._cmp(ctx)
                continue
            value = self._cmp(ctx)
        return value

    def _cmp(self, ctx):
        value = self._unary(ctx)
        op = self._peek()
        if op in ("==", "!="):
            self.pos += 1
            right = self._unary(ctx)
            equal = loose_equal(value, right)
            return equal if op == "==" else not equal
        return value

    def _unary(self, ctx):
        if self._peek() == "!":
            self.pos += 1
            return not self._unary(ctx)
        return self._primary(ctx)

    def _primary(self, ctx):
        tok = self._peek()
        if tok is None:
            raise AssertionError(f"truncated expression {self.text!r}")
        if tok == "(":
            self.pos += 1
            value = self._or(ctx)
            if self._peek() != ")":
                raise AssertionError(f"missing ) in {self.text!r}")
            self.pos += 1
            return value
        if isinstance(tok, tuple) and tok[0] == "str":
            self.pos += 1
            return tok[1]
        if isinstance(tok, tuple) and tok[0] == "id":
            self.pos += 1
            path = tok[1]
            if self._peek() == "(":
                self.pos += 1
                if self._peek() != ")":
                    raise AssertionError(f"only zero-arg functions are used, got {self.text!r}")
                self.pos += 1
                if path == "cancelled":
                    return bool(ctx.get("cancelled"))
                if path == "success":
                    return bool(ctx.get("success", True))
                raise AssertionError(f"unknown function {path}")
            value = ctx
            for part in path.split("."):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    value = None
                    break
            return value
        raise AssertionError(f"bad token {tok!r} in {self.text!r}")


def contains_status_function(expression: str) -> bool:
    body = expression.strip()
    if body.startswith("${{") and body.endswith("}}"):
        body = body[3:-2]
    for name in ("success(", "always(", "cancelled(", "failure("):
        if name in body.replace(" ", ""):
            return True
    return False


def interpolate(value, ctx: dict):
    if not isinstance(value, str) or "${{" not in value:
        return value
    out = []
    i = 0
    while i < len(value):
        start = value.find("${{", i)
        if start < 0:
            out.append(value[i:])
            break
        out.append(value[i:start])
        end = value.find("}}", start)
        if end < 0:
            raise AssertionError(f"unclosed expression in {value!r}")
        rendered = Expr(value[start : end + 2]).eval(ctx)
        out.append("" if rendered is None else str(rendered).lower() if isinstance(rendered, bool) else str(rendered))
        i = end + 2
    return "".join(out)


def run_git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class Repository:
    """Local stand-in for the repository actions/checkout fetches from."""

    def __init__(self, root: Path):
        self.bare = root / "origin.git"
        self.work = root / "seed"
        self.work.mkdir(parents=True)
        self.bare.mkdir()
        run_git(self.work, "init", "-b", "main")
        run_git(self.work, "config", "user.email", "storybook-test@example.invalid")
        run_git(self.work, "config", "user.name", "Storybook Test")
        self._write_tree(TRUSTED_MARKER.decode())
        run_git(self.work, "add", ".")
        run_git(self.work, "commit", "-m", "trusted storybook")
        self.main_sha = run_git(self.work, "rev-parse", "HEAD").stdout.strip()
        run_git(self.work, "tag", "v11.0.0")
        run_git(self.work, "tag", "v9.9.9")
        run_git(self.work, "checkout", "-b", "feature/evil")
        self._write_tree(ATTACKER_MARKER.decode(), malicious_action=True)
        run_git(self.work, "add", ".")
        run_git(self.work, "commit", "-m", "attacker storybook")
        self.attacker_sha = run_git(self.work, "rev-parse", "HEAD").stdout.strip()
        run_git(self.work, "branch", "v9.9.9")
        run_git(self.work, "tag", "v0.0.1")
        run_git(self.bare, "init", "--bare")
        run_git(self.bare, "config", "uploadpack.allowReachableSHA1InWant", "true")
        run_git(self.work, "remote", "add", "origin", str(self.bare))
        run_git(
            self.work,
            "push",
            "origin",
            "refs/heads/main",
            "refs/heads/feature/evil",
            "refs/heads/v9.9.9",
            "refs/tags/v11.0.0",
            "refs/tags/v9.9.9",
            "refs/tags/v0.0.1",
        )

    def _write_tree(self, marker: str, malicious_action: bool = False) -> None:
        package = {
            "name": "storybook-fixture",
            "scripts": {"storybook:build": "node build.js"},
        }
        (self.work / "package.json").write_text(json.dumps(package))
        (self.work / "build.js").write_text(
            textwrap.dedent(
                f"""\
                const fs = require('fs');
                const path = require('path');
                const out = path.join('packages', 'grafana-ui', 'dist', 'storybook');
                fs.mkdirSync(out, {{recursive: true}});
                fs.writeFileSync(path.join(out, 'index.html'), {marker!r});
                require('./record.js')('storybook:build');
                """
            )
        )
        (self.work / "record.js").write_text(
            textwrap.dedent(
                """\
                const fs = require('fs');
                function record(step) {
                  const token = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
                  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
                  const row = {
                    step,
                    tokenPresent: Boolean(token),
                    urlPresent: Boolean(url),
                    head: process.env.FIXTURE_HEAD || '',
                  };
                  fs.appendFileSync(process.env.OBSERVATION_FILE, JSON.stringify(row) + '\\n');
                }
                module.exports = record;
                if (require.main === module) {
                  record(process.argv[2] || 'unknown');
                }
                """
            )
        )
        action_dir = self.work / ".github/actions/yarn-install"
        action_dir.mkdir(parents=True, exist_ok=True)
        setup_dir = self.work / ".github/actions/setup-node"
        setup_dir.mkdir(parents=True, exist_ok=True)
        (setup_dir / "action.yml").write_text(
            "name: Setup\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: node record.js setup-node\n"
        )
        detect = self.work / ".github/actions/change-detection"
        detect.mkdir(parents=True, exist_ok=True)
        # The published change-detection action's changed-files step is limited
        # to pull_request events, so on push its frontend-packages output is 'true'.
        (detect / "action.yml").write_text(
            "name: Detect\noutputs:\n  frontend-packages:\n    value: 'true'\n"
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo detected\n"
        )
        if malicious_action:
            (action_dir / "action.yml").write_text(
                "name: Install\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: node record.js yarn-install\n"
            )
        else:
            (action_dir / "action.yml").write_text(
                "name: Install\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: node record.js yarn-install\n"
            )


def get_ref_spec(ref: str, commit: str) -> list[str]:
    """actions/checkout ref-helper.ts getRefSpec at fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09."""
    if not ref and not commit:
        raise AssertionError("ref and commit cannot both be empty")
    upper = (ref or "").upper()
    if commit:
        if upper.startswith("REFS/HEADS/"):
            branch = ref[len("refs/heads/") :]
            return [f"+{commit}:refs/remotes/origin/{branch}"]
        if upper.startswith("REFS/PULL/"):
            branch = ref[len("refs/pull/") :]
            return [f"+{commit}:refs/remotes/pull/{branch}"]
        if upper.startswith("REFS/TAGS/"):
            return [f"+{commit}:{ref}"]
        return [commit]
    if not upper.startswith("REFS/"):
        return [
            f"+refs/heads/{ref}*:refs/remotes/origin/{ref}*",
            f"+refs/tags/{ref}*:refs/tags/{ref}*",
        ]
    if upper.startswith("REFS/HEADS/"):
        branch = ref[len("refs/heads/") :]
        return [f"+{ref}:refs/remotes/origin/{branch}"]
    if upper.startswith("REFS/PULL/"):
        branch = ref[len("refs/pull/") :]
        return [f"+{ref}:refs/remotes/pull/{branch}"]
    return [f"+{ref}:{ref}"]


def resolve_checkout_inputs(ref_input: str, github_ref: str, github_sha: str) -> tuple[str, str]:
    """actions/checkout input-helper.ts getInputs ref handling, same commit as get_ref_spec."""
    ref = ref_input
    commit = ""
    if not ref:
        ref = github_ref
        commit = github_sha
        if commit and ref and not ref.startswith("refs/"):
            ref = f"refs/heads/{ref}"
    elif len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref):
        commit = ref
        ref = ""
    return ref, commit


def checkout_action(workspace: Path, origin: Path, ref_input: str, github_ref: str, github_sha: str) -> str:
    """Run the fetch and checkout commands actions/checkout runs for this ref.

    Fetch depth defaults to 1 (input-helper.ts). Fetch uses --no-tags unless the
    refspec is the all-tags spec (git-command-manager.ts fetch). Checkout uses
    `git checkout --force -B <branch> <start>` when a branch matches, which is
    tested before a same-named tag (ref-helper.ts getCheckoutInfo).
    """
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    run_git(workspace, "init", "-b", "placeholder")
    run_git(workspace, "remote", "add", "origin", str(origin))
    ref, commit = resolve_checkout_inputs(ref_input, github_ref, github_sha)
    refspec = get_ref_spec(ref, commit)
    fetch = ["-c", "protocol.version=2", "fetch", "--no-tags", "--prune", "--no-recurse-submodules", "--depth=1", "origin", *refspec]
    run_git(workspace, *fetch)
    upper = (ref or "").upper()
    if not ref:
        start = ""
        checkout_ref = commit
    elif upper.startswith("REFS/HEADS/"):
        branch = ref[len("refs/heads/") :]
        checkout_ref = branch
        start = f"refs/remotes/origin/{branch}"
    elif upper.startswith("REFS/TAGS/"):
        checkout_ref = ref
        start = ""
    elif not upper.startswith("REFS/"):
        listed = run_git(workspace, "branch", "--list", "--remote", f"origin/{ref}").stdout.strip()
        if listed:
            checkout_ref = ref
            start = f"refs/remotes/origin/{ref}"
        else:
            tags = run_git(workspace, "tag", "--list", ref).stdout.strip()
            if not tags:
                raise AssertionError(f"branch or tag {ref!r} was not fetched")
            checkout_ref = f"refs/tags/{ref}"
            start = ""
    else:
        checkout_ref = commit or ref
        start = ""
    args = ["checkout", "--force"]
    if start:
        args.extend(["-B", checkout_ref, start])
    else:
        args.append(checkout_ref)
    run_git(workspace, *args)
    return run_git(workspace, "rev-parse", "HEAD").stdout.strip()


class Simulation:
    def __init__(self, repo: Repository, observation: Path):
        self.repo = repo
        self.observation = observation
        self.bucket = {
            f"{PROD_BUCKET}/latest/index.html": PREEXISTING,
            f"{PROD_BUCKET}/canary/index.html": PREEXISTING,
        }
        self.observations: list[dict] = []
        self.artifacts: dict[str, dict[str, bytes]] = {}
        self.jobs_ran: list[str] = []
        self.checkouts: list[tuple[str, str]] = []
        self.authenticated_as: list[str] = []

    def object(self, bucket: str, key: str) -> bytes | None:
        return self.bucket.get(f"{bucket}/{key}")


def _truthy(value) -> bool:
    return value not in (False, 0, 0.0, "", None)


def _context(event: dict, steps: dict, env: dict, job_success: bool) -> dict:
    return {
        "cancelled": False,
        "success": job_success,
        "github": {
            "repository": event["repository"],
            "event_name": event["event_name"],
            "ref": event["ref"],
            "sha": event["sha"],
        },
        "inputs": event["inputs"],
        "needs": event["needs"],
        "steps": steps,
        "env": env,
    }


def _job_should_run(job: dict, event: dict) -> bool:
    needs = job.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    expression = job.get("if")
    blocked = False
    for name in needs:
        status = event["job_status"].get(name)
        if status in ("skipped", "failure"):
            blocked = True
    if expression is None:
        return not blocked
    if blocked and not contains_status_function(str(expression)):
        return False
    ctx = _context(event, {}, {}, job_success=not blocked)
    return bool(Expr(str(expression)).eval(ctx))


def _run_bash(workspace: Path, script: str, env: dict) -> None:
    subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=workspace,
        check=True,
        env=env,
        text=True,
    )


def _execute_package_script(workspace: Path, script_name: str, env: dict) -> None:
    """Yarn 4.17.1 executePackageScript runs manifest.scripts[name] through its shell."""
    package_json = json.loads((workspace / "package.json").read_text())
    script = package_json.get("scripts", {}).get(script_name)
    if script is None:
        raise AssertionError(f"package.json has no script {script_name}")
    _run_bash(workspace, script, env)


def _step_env(base: dict, job: dict, oidc: bool, workspace: Path, observation: Path, head: str) -> dict:
    env = os.environ.copy()
    env.update({key: "" if value is None else str(value) for key, value in base.items()})
    env["GITHUB_WORKSPACE"] = str(workspace)
    env["OBSERVATION_FILE"] = str(observation)
    env["FIXTURE_HEAD"] = head
    if oidc:
        # actions/runner ScriptHandler.cs copies GenerateIdTokenUrl into every script step.
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST_TOKEN
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = OIDC_REQUEST_URL
    else:
        env.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
        env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    return env


def _load_observations(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _copy_tree(source: Path) -> dict[str, bytes]:
    files = {}
    if source.is_file():
        files[source.name] = source.read_bytes()
        return files
    if not source.exists():
        raise AssertionError(f"artifact path does not exist: {source}")
    for file in source.rglob("*"):
        if file.is_file():
            files[str(file.relative_to(source))] = file.read_bytes()
    return files


def _materialize(files: dict[str, bytes], dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name, content in files.items():
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _gcloud_rm(sim: Simulation, url: str) -> None:
    prefix = url.removeprefix("gs://")
    if prefix.endswith("/**"):
        prefix = prefix[: -len("/**")]
    prefix = prefix.rstrip("/") + "/"
    for key in list(sim.bucket):
        if key.startswith(prefix) or key == prefix.rstrip("/"):
            del sim.bucket[key]


def _login(sim: Simulation, service_account: str, oidc: bool) -> None:
    if not oidc:
        raise RuntimeError("google-github-actions/auth requires ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    # workload_identity_federation.ts createCredentialsFile sets this when a service account is given.
    sim.authenticated_as.append(service_account)


def _upload_prefix(sim: Simulation, bucket: str, prefix: str, files: dict[str, bytes]) -> None:
    for name, content in files.items():
        key = "/".join(part for part in (bucket, prefix.strip("/"), name) if part)
        sim.bucket[key] = content


def _uses_name(uses: str) -> str:
    return uses.split("@", 1)[0]


def _run_steps(sim: Simulation, workspace: Path, steps: list, event: dict, oidc: bool, job_name: str) -> None:
    step_outputs: dict = {}
    env_map = dict(event["job_env"])
    for step in steps:
        step_if = step.get("if")
        if step_if is not None:
            ctx = _context(event, step_outputs, env_map, True)
            if not Expr(str(step_if)).eval(ctx):
                continue
        step_env_map = dict(env_map)
        for key, value in (step.get("env") or {}).items():
            step_env_map[key] = interpolate(value, _context(event, step_outputs, env_map, True))
        head = ""
        if (workspace / ".git").exists():
            head = run_git(workspace, "rev-parse", "HEAD").stdout.strip()
        env = _step_env(step_env_map, {}, oidc, workspace, sim.observation, head)
        env["GITHUB_OUTPUT"] = str(workspace / ".github_output")
        (workspace / ".github_output").write_text("")
        uses = step.get("uses")
        returned: dict = {}
        if uses:
            returned = _run_uses(
                sim, workspace, uses, step.get("with") or {}, event, oidc, step_outputs, env, job_name
            )
        elif step.get("run"):
            script = interpolate(step["run"], _context(event, step_outputs, step_env_map, True))
            stripped = script.strip()
            if stripped == "yarn storybook:build":
                _execute_package_script(workspace, "storybook:build", env)
            elif "gcloud storage rm" in script:
                # The workflow shell deletes the prefix, then ignores a missing prefix.
                for line in script.splitlines():
                    if "gcloud storage rm" not in line:
                        continue
                    quoted = line.split('"', 2)[1]
                    _gcloud_rm(sim, quoted)
            else:
                _run_bash(workspace, script, env)
        output_text = (workspace / ".github_output").read_text() if (workspace / ".github_output").exists() else ""
        outputs = {}
        for line in output_text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                outputs[key] = value
        outputs.update(returned)
        step_id = step.get("id")
        if step_id:
            step_outputs[step_id] = {"outputs": outputs}
        event["steps"] = step_outputs


def _run_uses(sim, workspace, uses, with_inputs, event, oidc, step_outputs, env, job_name) -> dict:
    ctx = _context(event, step_outputs, event["job_env"], True)
    inputs = {key: interpolate(value, ctx) for key, value in with_inputs.items()}
    name = _uses_name(uses)
    if name == "actions/checkout":
        ref_input = inputs.get("ref") or ""
        sha = checkout_action(workspace, sim.repo.bare, ref_input, event["ref"], event["sha"])
        sim.checkouts.append((job_name, sha))
        return {}
    if name.startswith("./"):
        # ActionManager.cs loads a self repository action from github.workspace.
        action_path = workspace / name[2:]
        manifest_path = action_path / "action.yml"
        if not manifest_path.exists():
            manifest_path = action_path / "action.yaml"
        manifest = load_workflow(manifest_path)
        runs = manifest.get("runs") or {}
        if runs.get("using") != "composite":
            raise AssertionError(f"unsupported local action {uses}")
        nested_event = dict(event)
        nested_event["job_env"] = dict(event["job_env"])
        nested_event["steps"] = {}
        _run_steps(sim, workspace, runs.get("steps") or [], nested_event, oidc, job_name)
        rendered = {}
        for key, spec in (manifest.get("outputs") or {}).items():
            value = spec.get("value") if isinstance(spec, dict) else spec
            if isinstance(value, str) and "${{" in value:
                rendered[key] = Expr(value).eval(_context(nested_event, nested_event.get("steps") or {}, {}, True))
            else:
                rendered[key] = value
        return rendered
    if name == "grafana/shared-workflows/actions/login-to-gcs":
        sa = inputs.get("service_account") or ""
        _login(sim, sa, oidc)
        return {}
    if name == "grafana/shared-workflows/actions/push-to-gcs":
        sa = inputs.get("service_account") or ""
        bucket = inputs.get("bucket") or ""
        if bucket and sa:
            _login(sim, sa, oidc)
        source = workspace / inputs["path"]
        _upload_prefix(sim, bucket, inputs.get("bucket_path") or "", _copy_tree(source))
        return {}
    if name == "actions/upload-artifact":
        source = workspace / inputs["path"]
        sim.artifacts[inputs["name"]] = _copy_tree(source)
        return {}
    if name == "actions/download-artifact":
        files = sim.artifacts[inputs["name"]]
        dest = workspace / inputs.get("path", inputs["name"])
        _materialize(files, dest)
        return {}
    if name in {"actions/setup-node", "actions/cache"} or name.startswith("grafana/grafana-github-actions-go/"):
        return {}
    raise AssertionError(f"workflow step uses {uses}, which this test does not execute")


def run_jobs(workflow: dict, event: dict, sim: Simulation, workspace_root: Path) -> None:
    jobs = workflow["jobs"]
    pending = dict(jobs)
    event = dict(event)
    event.setdefault("needs", {})
    event.setdefault("job_status", {})
    while pending:
        ready = [
            name
            for name, job in pending.items()
            if all(need in event["job_status"] for need in ([job["needs"]] if isinstance(job.get("needs"), str) else job.get("needs") or []))
        ]
        if not ready:
            raise AssertionError(f"job cycle or missing need in {list(pending)}")
        name = ready[0]
        job = pending.pop(name)
        if "uses" in job:
            called = DEPLOY_WORKFLOW if job["uses"].endswith("deploy-storybook.yml@main") or job["uses"].endswith("deploy-storybook.yml") else None
            if called is None:
                raise AssertionError(f"unsupported reusable workflow {job['uses']}")
            if not _job_should_run(job, event):
                event["job_status"][name] = "skipped"
                continue
            ctx = _context(event, {}, {}, True)
            passed = {key: interpolate(value, ctx) for key, value in (job.get("with") or {}).items()}
            called_event = dict(event)
            called_event["inputs"] = passed
            called_event["event_name"] = event["event_name"]
            called_event["needs"] = {}
            called_event["job_status"] = {}
            run_jobs(load_workflow(called), called_event, sim, workspace_root)
            event["job_status"][name] = "success"
            continue
        if not _job_should_run(job, event):
            event["job_status"][name] = "skipped"
            event["needs"][name] = {"outputs": {}}
            continue
        sim.jobs_ran.append(name)
        workspace = workspace_root / name
        workspace.mkdir(parents=True)
        permissions = job.get("permissions") or {}
        oidc = permissions.get("id-token") == "write"
        job_env = {}
        for key, value in (job.get("env") or {}).items():
            job_env[key] = interpolate(value, _context(event, {}, {}, True))
        step_event = dict(event)
        step_event["job_env"] = job_env
        step_event["steps"] = {}
        _run_steps(sim, workspace, job.get("steps") or [], step_event, oidc, name)
        outputs = {}
        output_ctx = _context(step_event, step_event.get("steps") or {}, job_env, True)
        for key, value in (job.get("outputs") or {}).items():
            if isinstance(value, str) and "${{" in value:
                outputs[key] = Expr(value).eval(output_ctx)
            else:
                outputs[key] = value
        event["needs"][name] = {"outputs": outputs}
        event["job_status"][name] = "success"
    sim.observations = _load_observations(sim.observation)


def dispatch_event(repo: Repository, version: str, event_name: str = "workflow_dispatch") -> dict:
    return {
        "repository": "grafana/grafana",
        "event_name": event_name,
        "ref": "refs/heads/main",
        "sha": repo.main_sha,
        "inputs": {"version": version},
        "needs": {},
        "job_status": {},
        "job_env": {},
    }


def simulate_deploy(repo: Repository, root: Path, event: dict) -> Simulation:
    observation = root / "observations.jsonl"
    sim = Simulation(repo, observation)
    run_jobs(load_workflow(DEPLOY_WORKFLOW), event, sim, root / "jobs")
    return sim


class DeployStorybookRefTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = Repository(self.root / "repo")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_expression_runs_deploy_for_caller_chosen_branch(self) -> None:
        workflow = load_workflow(DEPLOY_WORKFLOW)
        expression = workflow["jobs"]["deploy-storybook"]["if"]
        ctx = {
            "cancelled": False,
            "github": {"repository": "grafana/grafana", "event_name": "workflow_dispatch"},
            "inputs": {"version": "feature/evil"},
            "needs": {"detect-changes": {"outputs": {"changed-frontend-packages": None}}},
        }
        self.assertTrue(Expr(str(expression)).eval(ctx))
        self.assertIn("id-token", workflow["jobs"]["deploy-storybook"]["permissions"])
        checkout = workflow["jobs"]["deploy-storybook"]["steps"][0]
        self.assertEqual(checkout["with"]["ref"], "${{ inputs.version }}")

    def test_dispatch_branch_does_not_receive_oidc_or_publish(self) -> None:
        sim = simulate_deploy(self.repo, self.root / "branch", dispatch_event(self.repo, "feature/evil"))
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), PREEXISTING)
        self.assertEqual(sim.object(PROD_BUCKET, "canary/index.html"), PREEXISTING)
        self.assertNotIn(PROD_SA, sim.authenticated_as)

    def test_branch_shadowing_release_tag_is_not_published(self) -> None:
        # actions/checkout resolves an unqualified ref to a branch before a tag.
        sim = simulate_deploy(self.repo, self.root / "shadow", dispatch_event(self.repo, "v9.9.9"))
        self.assertNoOidc(sim)
        published = b"\n".join(sim.bucket.values())
        self.assertNotIn(ATTACKER_MARKER, published)
        self.assertNotIn(self.repo.attacker_sha, [sha for _, sha in sim.checkouts if sha == self.repo.attacker_sha and _ == "deploy-storybook"])

    def test_attacker_commit_sha_is_not_published(self) -> None:
        sim = simulate_deploy(self.repo, self.root / "sha", dispatch_event(self.repo, self.repo.attacker_sha))
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), PREEXISTING)
        self.assertNotIn(PROD_SA, sim.authenticated_as)

    def test_release_workflow_call_forwards_version_without_publishing_a_branch(self) -> None:
        release = load_workflow(RELEASE_WORKFLOW)
        job = release["jobs"]["deploy-storybook"]
        event = {
            "repository": "grafana/grafana",
            "event_name": "workflow_dispatch",
            "ref": "refs/heads/main",
            "sha": self.repo.main_sha,
            "inputs": {"version": "feature/evil", "latest": "1", "dry_run": False},
            "needs": {},
            "job_status": {"main": "success"},
            "job_env": {},
        }
        self.assertTrue(_job_should_run(job, event))
        self.assertEqual(Expr(job["with"]["version"]).eval(_context(event, {}, {}, True)), "feature/evil")
        sim = Simulation(self.repo, self.root / "release-obs.jsonl")
        run_jobs(release, event, sim, self.root / "release-jobs")
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), PREEXISTING)
        self.assertNotIn(PROD_SA, sim.authenticated_as)

    def test_unreleased_tag_pointing_at_attacker_commit_is_not_published(self) -> None:
        sim = simulate_deploy(self.repo, self.root / "badtag", dispatch_event(self.repo, "v0.0.1"))
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), PREEXISTING)
        self.assertNotIn(ATTACKER_MARKER, b"\n".join(sim.bucket.values()))

    def test_release_tag_publishes_without_the_build_seeing_oidc(self) -> None:
        sim = simulate_deploy(self.repo, self.root / "tag", dispatch_event(self.repo, "v11.0.0"))
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), TRUSTED_MARKER)
        self.assertEqual(sim.object(PROD_BUCKET, "canary/index.html"), PREEXISTING)
        self.assertIn(PROD_SA, sim.authenticated_as)

    def test_push_to_default_branch_publishes_canary_without_oidc_in_the_build(self) -> None:
        event = {
            "repository": "grafana/grafana",
            "event_name": "push",
            "ref": "refs/heads/main",
            "sha": self.repo.main_sha,
            "inputs": {"version": None},
            "needs": {},
            "job_status": {},
            "job_env": {},
        }
        sim = simulate_deploy(self.repo, self.root / "push", event)
        self.assertNoOidc(sim)
        self.assertEqual(sim.object(PROD_BUCKET, "canary/index.html"), TRUSTED_MARKER)
        self.assertEqual(sim.object(PROD_BUCKET, "latest/index.html"), PREEXISTING)

    def assertNoOidc(self, sim: Simulation) -> None:
        seen = [row for row in sim.observations if row.get("tokenPresent") or row.get("urlPresent")]
        self.assertEqual(seen, [], f"repository code requested an OIDC token: {seen}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
