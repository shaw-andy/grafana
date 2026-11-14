#!/usr/bin/env python3
"""Installation tokens must not be handed to an action selected by a moving ref.

These tests fail while a workflow passes a GitHub App installation token to a
remote action referenced by a branch, tag, or other non-SHA ref. They pass
when every such action is pinned to a full 40-character commit SHA, or the
token is no longer passed into a moving ref.

The tests follow the runner, not a text search:

- actions/runner v2.338.2 ActionManager.GetDownloadInfoAsync sends the uses
  ref through unchanged (ActionManager.cs:1037-1041) and later downloads
  ResolvedSha (ActionManager.cs:1212). A 40-hex ref is that commit. Any other
  ref is resolved again at use time, so a check that sampled the branch tip
  earlier does not stick.
- CompositeActionHandler copies step inputs into the embedded step's inputs
  context (CompositeActionHandler.cs:98-144) and EvaluateStepEnvironment
  writes those values into the step environment (CompositeActionHandler.cs:287-295).
- The pinned create-github-app-token action (46f48da11e78ebdba7a8747ae456b11062fac83e)
  writes the installation token to the step output named token. migrate-open-prs
  on the moving ref reads it as GITHUB_TOKEN and, in the product, passes it to
  go-github v50.2.0 PullRequests.Edit.

Left untested, because they are not this handoff:

- Shell steps and local actions (./.github/actions/...) that use the token
  inside this same commit. Changing those requires write access to this
  repository, which can already change the workflow that mints the token.
- secrets.GITHUB_TOKEN passed to a floating action (github-release.yml,
  community-release.yml, pr-checks.yml, pr-commands.yml, stale.yml,
  documentation-ci.yml). That is the job token, not the installation token
  minted for grafana-pr-automation.
- Vault secrets other than that installation token (Crowdin, forum, OpenAI)
  passed to a floating action.
- Whether the pr-writer permission set's repository list includes
  grafana/grafana-enterprise. That list is in Vault, which is not in this
  repository. The enterprise caller is still exercised: the action receives
  the token together with that ownerRepo.
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
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
MINT_ACTION = "create-github-app-token"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
TOKEN_EXPR = re.compile(
    r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.token\s*\}\}",
    re.IGNORECASE,
)
INPUT_EXPR = re.compile(r"^inputs(?:\.([A-Za-z0-9_-]+)|\['([^']+)'\])$", re.IGNORECASE)

# create_token.sh and auth_vault.sh at
# grafana/shared-workflows 46f48da11e78ebdba7a8747ae456b11062fac83e
# actions/create-github-app-token/. The workflow pins that action.
AUTH_VAULT_SH = r"""#!/bin/bash
set -euo pipefail

TEMP_FILE=$(mktemp)
echo "Using temporary file: ${TEMP_FILE}"
trap 'rm -f "${TEMP_FILE}"' EXIT

MAX_ATTEMPTS=3
for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
    echo "Attempt ${attempt} to authenticate with Vault..."

    RESPONSE=$(curl -sS -w "%{http_code}" -o "${TEMP_FILE}" \
        -X POST "${VAULT_URL}/v1/auth/github-actions-oidc/login" \
        -H "Content-Type: application/json" \
        -H "Proxy-Authorization-Token: Bearer ${GITHUB_JWT_PROXY}" \
        -d "{
            \"role\": \"${REPOSITORY_NAME}-${REF_SHA}-${PERMISSION_SET}\",
            \"jwt\": \"${GITHUB_JWT_VAULT}\"
        }" || true)

    if [[ "${RESPONSE}" -eq 200 ]]; then
        TOKEN=$(sed -n 's/.*"client_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${TEMP_FILE}" | head -n1)
        if [[ -z "${TOKEN}" ]]; then
            echo "Failed to parse client_token from Vault response"
            exit 1
        fi
        echo "::add-mask::$TOKEN"
        echo "vault_token=${TOKEN}" >> "${GITHUB_OUTPUT}"
        echo "Vault auth done!"
        exit 0
    else
        echo "Vault auth failed (HTTP ${RESPONSE})"
        cat "${TEMP_FILE}" || true
        sleep $((attempt * 5))
    fi
done

echo "Failed to authenticate with Vault after ${MAX_ATTEMPTS} attempts"
exit 1
"""

CREATE_TOKEN_SH = r"""#!/bin/bash
set -euo pipefail

MAX_ATTEMPTS=3
IFS=',' read -ra APPS <<< "${GITHUB_APP}"
setRandomApp() {
    GITHUB_APP=$(printf "%s\n" "${APPS[@]}" | sed 's/^ *//;s/ *$//' | shuf -n1)
    echo "Randomly selected GitHub App: ${GITHUB_APP}"
}

TEMP_FILE=$(mktemp)
echo "Using temporary file: ${TEMP_FILE}"
trap 'rm -f "${TEMP_FILE}"' EXIT

for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
    echo "Attempt ${attempt} to get GitHub token..."
    setRandomApp
    RESPONSE=$(curl -sS -w "%{http_code}" -o "${TEMP_FILE}" \
        "${VAULT_URL}/v1/github-app-${GITHUB_APP}/token/${REPOSITORY_NAME}-${REF_SHA}-${PERMISSION_SET}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Proxy-Authorization-Token: Bearer ${GITHUB_JWT_PROXY}" || true)

    if [[ "${RESPONSE}" -eq 200 ]]; then
        TOKEN=$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${TEMP_FILE}" | head -n1)
        if [[ -z "${TOKEN}" ]]; then
            echo "Failed to parse token from Vault response"
            exit 1
        fi
        echo "::add-mask::$TOKEN"
        echo "github_token=${TOKEN}" >> "${GITHUB_OUTPUT}"
        echo "Create GitHub Token done!"
        exit 0
    else
        echo "Vault request failed (HTTP ${RESPONSE})"
        cat "${TEMP_FILE}" || true
        sleep $((attempt * 5))
    fi
done

echo "Failed to retrieve GitHub token after ${MAX_ATTEMPTS} attempts"
exit 1
"""

# Same request the product's migrate-open-prs binary sends. go-github v50.2.0
# NewTokenClient wraps oauth2.StaticTokenSource; Transport.RoundTrip calls
# Token.SetAuthHeader, which sets "Authorization: Bearer <token>".
# PullRequests.Edit sends PATCH repos/{owner}/{repo}/pulls/{number} with the
# new base branch in the JSON "base" field when the pull request is not closed.
RETARGET_GO = r"""package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/google/go-github/v50/github"
)

func main() {
	api := os.Getenv("GITHUB_API")
	baseURL, err := url.Parse(api)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	owner := os.Getenv("TARGET_OWNER")
	repo := os.Getenv("TARGET_REPO")
	base := os.Getenv("TARGET_BASE")
	if owner == "" {
		owner = "grafana"
	}
	if repo == "" {
		repo = "grafana"
	}
	if base == "" {
		base = "release-11.2.4"
	}
	n, _ := strconv.Atoi(os.Getenv("IN_COUNT"))
	var candidates []string
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		candidates = append(candidates, v)
	}
	for i := 0; i < n; i++ {
		if v := os.Getenv(fmt.Sprintf("IN_%d", i)); v != "" {
			candidates = append(candidates, v)
		}
	}
	ctx := context.Background()
	for _, candidate := range candidates {
		client := github.NewTokenClient(ctx, candidate)
		client.BaseURL = baseURL
		_, resp, _ := client.PullRequests.Edit(ctx, owner, repo, 1, &github.PullRequest{
			Base: &github.PullRequestBranch{Ref: github.String(base)},
		})
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}
}
"""


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.record("POST", self.path, self.headers, body)
        payload = json.dumps({"auth": {"client_token": "placeholder-vault-token"}}).encode()
        self._ok(payload)

    def do_GET(self):
        self.server.record("GET", self.path, self.headers, b"")
        payload = json.dumps({"token": "placeholder-installation-token"}).encode()
        self._ok(payload)

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.record("PATCH", self.path, self.headers, body)
        self._ok(b"{}")

    def _ok(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class RecordingServer(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), RecordingHandler)
        self.events = []
        self._lock = threading.Lock()

    def record(self, method, path, headers, body):
        with self._lock:
            self.events.append(
                {
                    "method": method,
                    "path": path,
                    "authorization": headers.get("Authorization", ""),
                    "body": body,
                }
            )

    def clear(self):
        with self._lock:
            self.events.clear()

    def snapshot(self):
        with self._lock:
            return list(self.events)


def load_workflow(path: Path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def split_uses(uses: str):
    uses = str(uses).strip().split()[0]
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return {"raw": uses, "name": uses, "path": "", "ref": ""}
    left, ref = uses.rsplit("@", 1)
    parts = left.split("/")
    if len(parts) < 2:
        return None
    return {
        "raw": uses,
        "name": "/".join(parts[:2]),
        "path": "/".join(parts[2:]),
        "ref": ref,
    }


def mint_step_ids(job: dict) -> set[str]:
    found = set()
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = str(step.get("uses") or "")
        if MINT_ACTION in uses and step.get("id"):
            found.add(str(step["id"]).lower())
    return found


def carries_installation_token(value, mint_ids: set[str]) -> bool:
    if not isinstance(value, str):
        return False
    for match in TOKEN_EXPR.finditer(value):
        if match.group(1).lower() in mint_ids:
            return True
    return False


def iter_handoffs():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        document = load_workflow(path)
        if not isinstance(document, dict):
            continue
        jobs = document.get("jobs") or {}
        if not isinstance(jobs, dict):
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            mint_ids = mint_step_ids(job)
            blocks = []
            if job.get("uses"):
                blocks.append(("job", job_name, job))
            for index, step in enumerate(job.get("steps") or []):
                if isinstance(step, dict) and step.get("uses"):
                    blocks.append(("step", f"{job_name}#{index}:{step.get('name') or step.get('id') or index}", step))
            for kind, where, block in blocks:
                mapping = {}
                for section in ("with", "env"):
                    values = block.get(section) or {}
                    if isinstance(values, dict):
                        mapping.update(values)
                if not any(carries_installation_token(v, mint_ids) for v in mapping.values()):
                    continue
                parsed = split_uses(block["uses"])
                if parsed is None:
                    continue
                yield {
                    "file": path.name,
                    "where": where,
                    "kind": kind,
                    "uses": parsed,
                    "mapping": {str(k): v for k, v in mapping.items()},
                    "mint_ids": mint_ids,
                }


def permission_set_for(ref_name: str) -> str:
    """Evaluate the migrate-prs.yml permission_set expression.

    startsWith is ordinal-and-case-insensitive. `&&` returns the first falsy
    value, otherwise the last value. `||` returns the first truthy value,
    otherwise the last value. A boolean false is falsy and a non-empty string
    is truthy.
    """
    matched = ref_name.casefold().startswith("release-".casefold())
    if matched:
        return "pr-writer-release"
    return "pr-writer-main"


def workflow_ref_sha(workflow_ref: str) -> str:
    # action.yaml normalize-workflow-name at the pinned create-github-app-token.
    script = r"""
RAW_NAME="$WORKFLOW_REF"
REF_SHA=$(echo -n "$RAW_NAME" | sed -E 's|^[^/]*/[^/]*/||' | sed -E 's/@.*//' | sha256sum | awk '{print $1}')
printf '%s' "$REF_SHA"
"""
    completed = subprocess.run(
        ["bash", "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "WORKFLOW_REF": workflow_ref},
    )
    return completed.stdout.strip()


def read_output(path: Path, key: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise AssertionError(f"mint step did not write {key}")


def run_shell(script: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
    )


class ActionFixture:
    def __init__(self, root: Path, handoffs, retarget_bin: Path):
        self.root = root
        self.repo = root / "actions"
        self.retarget_bin = retarget_bin
        keys_for_path: dict[str, list[str]] = {}
        for handoff in handoffs:
            directory = handoff["uses"]["path"]
            keys = keys_for_path.setdefault(directory, [])
            for key in handoff["mapping"]:
                if key not in keys:
                    keys.append(key)
        self.repo.mkdir(parents=True)
        self._git("init", "-b", "fixture")
        self._git("config", "user.email", "token-pin-test@example.com")
        self._git("config", "user.name", "token-pin-test")
        self._write_tree(keys_for_path, malicious=False)
        self._git("add", "-A")
        self._git("commit", "-m", "honest action")
        self.honest = self._rev_parse("HEAD")
        self._write_tree(keys_for_path, malicious=True)
        self._git("add", "-A")
        self._git("commit", "-m", "moving ref keeps the token input")
        self.malicious = self._rev_parse("HEAD")

    def _git(self, *args, check=True):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=check,
            capture_output=True,
            text=True,
        )

    def _rev_parse(self, ref: str) -> str:
        return self._git("rev-parse", ref).stdout.strip()

    def _write_tree(self, keys_for_path: dict[str, list[str]], malicious: bool):
        for directory, keys in keys_for_path.items():
            folder = self.repo / directory if directory else self.repo
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "action.yml").write_text(
                self._action_yml(keys, malicious),
                encoding="utf-8",
            )

    def _action_yml(self, keys: list[str], malicious: bool) -> str:
        if not malicious:
            return (
                "name: pinned\n"
                "runs:\n"
                "  using: composite\n"
                "  steps:\n"
                "    - shell: bash\n"
                "      run: printf 'identity=pinned-commit\\n' > \"$CAPTURE_FILE\"\n"
            )
        env_lines = []
        for index, key in enumerate(keys):
            env_lines.append(f"        IN_{index}: ${{{{ inputs['{key}'] }}}}")
        env = "\n".join(env_lines)
        owner_index = keys.index("ownerRepo") if "ownerRepo" in keys else None
        to_index = keys.index("to") if "to" in keys else None
        owner_snippet = ""
        if owner_index is not None:
            owner_snippet = (
                f'if [ -n "${{IN_{owner_index}:-}}" ]; then\n'
                f'  export TARGET_OWNER="${{IN_{owner_index}%%/*}}"\n'
                f'  export TARGET_REPO="${{IN_{owner_index}#*/}}"\n'
                "fi\n"
            )
        base_snippet = ""
        if to_index is not None:
            base_snippet = (
                f'if [ -n "${{IN_{to_index}:-}}" ]; then\n'
                f'  export TARGET_BASE="$IN_{to_index}"\n'
                "fi\n"
            )
        script = (
            "set -euo pipefail\n"
            "printf 'identity=moving-ref\\n' > \"$CAPTURE_FILE\"\n"
            "export TARGET_OWNER=grafana\n"
            "export TARGET_REPO=grafana\n"
            "export TARGET_BASE=release-11.2.4\n"
            f"export IN_COUNT={len(keys)}\n"
            + owner_snippet
            + base_snippet
            + '"$RETARGET_BIN"\n'
        )
        indented = "\n".join("          " + line if line else "" for line in script.splitlines())
        env_block = f"      env:\n{env}\n" if env else ""
        return (
            "name: moving\n"
            "inputs:\n"
            + "".join(f"  {key}:\n    required: false\n" for key in keys)
            + "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - shell: bash\n"
            + env_block
            + "      run: |\n"
            + indented
            + "\n"
        )

    def move_ref(self, ref: str, sha: str):
        self._git("update-ref", f"refs/heads/{ref}", sha)

    def resolve_at_use(self, ref: str) -> str:
        # A full commit SHA is not looked up as a branch. The runner sends it
        # as Ref and downloads that commit even if the branch moved.
        if FULL_SHA.fullmatch(ref or ""):
            return ref
        return self._rev_parse(ref)

    def action_yml(self, sha: str, directory: str) -> dict:
        spec = f"{sha}:{directory}/action.yml" if directory else f"{sha}:action.yml"
        text = self._git("show", spec).stdout
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            raise AssertionError("action.yml did not parse")
        return loaded


def eval_inputs_expr(value, inputs: dict):
    if not isinstance(value, str):
        return "" if value is None else str(value)
    match = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", value.strip())
    if not match:
        return value
    expr = match.group(1).strip()
    indexed = INPUT_EXPR.fullmatch(expr)
    if not indexed:
        return ""
    key = indexed.group(1) or indexed.group(2)
    for name, item in inputs.items():
        if name.lower() == key.lower():
            return "" if item is None else str(item)
    return ""


def evaluate_step_env(action: dict, inputs: dict) -> dict[str, str]:
    env: dict[str, str] = {}
    for step in (action.get("runs") or {}).get("steps") or []:
        for key, value in (step.get("env") or {}).items():
            env[str(key)] = eval_inputs_expr(value, inputs)
    return env


def substitute_token(value, mint_ids: set[str], token: str) -> str:
    if not isinstance(value, str):
        return "" if value is None else str(value)

    def replace(match: re.Match) -> str:
        if match.group(1).lower() in mint_ids:
            return token
        return match.group(0)

    return TOKEN_EXPR.sub(replace, value)


class UnpinnedInstallationTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="token-pin-"))
        cls.vault = RecordingServer()
        cls.github = RecordingServer()
        cls.vault_thread = threading.Thread(target=cls.vault.serve_forever, daemon=True)
        cls.github_thread = threading.Thread(target=cls.github.serve_forever, daemon=True)
        cls.vault_thread.start()
        cls.github_thread.start()
        cls.retarget_bin = cls.tmp / "retarget"
        build_dir = cls.tmp / "retargetsrc"
        build_dir.mkdir()
        (build_dir / "go.mod").write_text(
            "module retargettest\n\ngo 1.22\n\nrequire github.com/google/go-github/v50 v50.2.0\n",
            encoding="utf-8",
        )
        (build_dir / "main.go").write_text(RETARGET_GO, encoding="utf-8")
        tidy = subprocess.run(
            ["go", "mod", "tidy"],
            cwd=build_dir,
            capture_output=True,
            text=True,
        )
        if tidy.returncode != 0:
            raise AssertionError(tidy.stderr or tidy.stdout)
        built = subprocess.run(
            ["go", "build", "-o", str(cls.retarget_bin), "."],
            cwd=build_dir,
            capture_output=True,
            text=True,
        )
        if built.returncode != 0:
            raise AssertionError(built.stderr or built.stdout)
        cls.handoffs = list(iter_handoffs())
        cls.fixture = ActionFixture(cls.tmp, cls.handoffs, cls.retarget_bin)
        cls.token, cls.mint_paths = cls.mint("pr-writer-main")

    @classmethod
    def tearDownClass(cls):
        cls.vault.shutdown()
        cls.github.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def mint(cls, permission_set: str):
        vault_port = cls.vault.server_address[1]
        work = cls.tmp / "mint"
        work.mkdir(exist_ok=True)
        (work / "auth_vault.sh").write_text(AUTH_VAULT_SH, encoding="utf-8")
        (work / "create_token.sh").write_text(CREATE_TOKEN_SH, encoding="utf-8")
        os.chmod(work / "auth_vault.sh", 0o755)
        os.chmod(work / "create_token.sh", 0o755)
        workflow_ref = "grafana/grafana/.github/workflows/migrate-prs.yml@refs/heads/main"
        ref_sha = workflow_ref_sha(workflow_ref)
        output = work / "output"
        output.write_text("", encoding="utf-8")
        base_env = {
            "PATH": os.environ["PATH"],
            "VAULT_URL": f"http://127.0.0.1:{vault_port}",
            "REPOSITORY_NAME": "grafana",
            "PERMISSION_SET": permission_set,
            "GITHUB_APP": "grafana-pr-automation",
            "GITHUB_JWT_PROXY": "placeholder-oidc-jwt",
            "GITHUB_JWT_VAULT": "placeholder-oidc-jwt",
            "REF_SHA": ref_sha,
            "GITHUB_OUTPUT": str(output),
            "HOME": os.environ.get("HOME", str(work)),
        }
        cls.vault.clear()
        auth = run_shell(str(work / "auth_vault.sh"), base_env, work)
        if auth.returncode != 0:
            raise AssertionError(auth.stderr or auth.stdout)
        vault_token = read_output(output, "vault_token")
        output.write_text("", encoding="utf-8")
        minted = run_shell(
            str(work / "create_token.sh"),
            {**base_env, "VAULT_TOKEN": vault_token},
            work,
        )
        if minted.returncode != 0:
            raise AssertionError(minted.stderr or minted.stdout)
        token = read_output(output, "github_token")
        paths = [event["path"] for event in cls.vault.snapshot()]
        return token, paths

    def evaluated_mapping(self, handoff, caller_inputs: dict) -> dict[str, str]:
        evaluated = {}
        for key, value in handoff["mapping"].items():
            if isinstance(value, str) and "${{ inputs." in value:
                match = re.fullmatch(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}", value.strip())
                if match:
                    evaluated[key] = str(caller_inputs.get(match.group(1), ""))
                    continue
            evaluated[key] = substitute_token(value, handoff["mint_ids"], self.token)
        return evaluated

    def exercise(self, handoff, caller_inputs: dict):
        ref = handoff["uses"]["ref"]
        # Sample the tip, then move it before the job resolves the action.
        # ResolveActionDownloadInfo runs at use time and sends the ref string
        # from the workflow, not the SHA observed by an earlier check.
        self.fixture.move_ref("main", self.fixture.honest)
        checked = self.fixture.resolve_at_use("main")
        self.assertEqual(checked, self.fixture.honest)
        self.fixture.move_ref("main", self.fixture.malicious)
        if ref and not FULL_SHA.fullmatch(ref) and ref != "main":
            self.fixture.move_ref(ref, self.fixture.malicious)
        resolved = self.fixture.resolve_at_use(ref)
        if FULL_SHA.fullmatch(ref or ""):
            self.assertNotEqual(resolved, self.fixture.malicious)
            tree = self.fixture.honest
        else:
            self.assertEqual(resolved, self.fixture.malicious)
            tree = self.fixture.malicious
        action = self.fixture.action_yml(tree, handoff["uses"]["path"])
        inputs = self.evaluated_mapping(handoff, caller_inputs)
        env = evaluate_step_env(action, inputs)
        capture = self.tmp / "capture"
        if capture.exists():
            capture.unlink()
        self.github.clear()
        script = (action["runs"]["steps"][0].get("run") or "").strip() + "\n"
        completed = subprocess.run(
            ["bash", "-c", script],
            cwd=self.tmp,
            env={
                "PATH": os.environ["PATH"],
                "HOME": os.environ.get("HOME", str(self.tmp)),
                "CAPTURE_FILE": str(capture),
                "RETARGET_BIN": str(self.retarget_bin),
                "GITHUB_API": f"http://127.0.0.1:{self.github.server_address[1]}/",
                **env,
            },
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        identity = ""
        if capture.exists():
            for line in capture.read_text(encoding="utf-8").splitlines():
                if line.startswith("identity="):
                    identity = line.split("=", 1)[1]
        matched = []
        for event in self.github.snapshot():
            if event["method"] == "PATCH" and event["authorization"] == f"Bearer {self.token}":
                matched.append(event)
        return identity, matched

    def assert_token_stays_on_the_pinned_commit(self, handoff, caller_inputs, detail):
        identity, matched = self.exercise(handoff, caller_inputs)
        if identity == "moving-ref" and matched:
            event = matched[0]
            try:
                body = json.loads(event["body"].decode())
            except json.JSONDecodeError:
                body = {}
            self.fail(
                f"{handoff['file']} {handoff['where']} uses {handoff['uses']['raw']}. "
                f"The ref tip moved from {self.fixture.honest[:12]} at check time to "
                f"{self.fixture.malicious[:12]} before resolution, and that tip presented "
                f"the installation token on {event['method']} {event['path']} "
                f"with base {body.get('base')!r}. {detail}"
            )

    def test_release_migration_does_not_give_the_writer_token_to_a_moving_action(self):
        migrate = [
            item
            for item in self.handoffs
            if item["file"] == "migrate-prs.yml" and item["uses"]["path"] == "migrate-open-prs"
        ]
        self.assertEqual(len(migrate), 1)
        release = load_workflow(WORKFLOWS / "release-comms.yml")
        callers = []
        for name, job in (release.get("jobs") or {}).items():
            if isinstance(job, dict) and "migrate-prs.yml" in str(job.get("uses") or ""):
                callers.append((name, (job.get("with") or {}).get("ownerRepo")))
        self.assertCountEqual(
            [owner for _, owner in callers],
            ["grafana/grafana", "grafana/grafana-enterprise"],
        )
        cases = [
            ("42/merge", "pr-writer-main"),
            ("release-11.2.3", "pr-writer-release"),
        ]
        for ref_name, expected_set in cases:
            self.assertEqual(permission_set_for(ref_name), expected_set)
            token, paths = self.mint(expected_set)
            self.token = token
            self.assertTrue(
                any(path.endswith("-" + expected_set) for path in paths),
                paths,
            )
            for caller, owner in callers:
                with self.subTest(ref_name=ref_name, caller=caller, owner=owner):
                    self.assert_token_stays_on_the_pinned_commit(
                        migrate[0],
                        {
                            "ownerRepo": owner,
                            "from": "release-11.2.3",
                            "to": "release-11.2.4",
                        },
                        f"permission set {expected_set} was minted for ref_name {ref_name} "
                        f"and release-comms job {caller} supplied ownerRepo {owner}.",
                    )

    def test_every_installation_token_handoff_resolves_at_use_time(self):
        self.assertGreaterEqual(len(self.handoffs), 1)
        for handoff in self.handoffs:
            with self.subTest(file=handoff["file"], where=handoff["where"], uses=handoff["uses"]["raw"]):
                caller_inputs = {
                    "ownerRepo": "grafana/grafana",
                    "from": "release-11.2.3",
                    "to": "release-11.2.4",
                }
                self.assert_token_stays_on_the_pinned_commit(
                    handoff,
                    caller_inputs,
                    "The installation token output was an input of this action.",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
