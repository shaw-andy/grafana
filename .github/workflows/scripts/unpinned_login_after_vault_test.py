#!/usr/bin/env python3
"""Fail while a moving-ref action runs after Vault secrets were exported.

The frontend performance job pins get-vault-secrets at a revision that still
writes secrets into the job environment, then runs login-to-gar from the
moving main branch in that same job. The job also sets id-token: write.
This test replays that order with the action code those revisions ship and
with the runner's environment file and step-environment rules.

Run:
  python3 .github/workflows/scripts/unpinned_login_after_vault_test.py

The security assertion fails until every remote action that still runs after
those secrets are in the job environment is pinned to a full commit SHA, and
until login-to-gar in the performance job is pinned to a full commit SHA.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CACHE = Path(os.environ.get("UNPINNED_ACTION_CACHE", "/tmp/unpinned-login-after-vault-cache"))
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
PERFORMANCE_WORKFLOW = "frontend-perf-tests.yaml"

# Names the performance workflow asks Vault to place in the job environment.
# Values used here are placeholders, never real credentials.
PERFORMANCE_SECRET_NAMES = (
    "PROMETHEUS_URL",
    "PROMETHEUS_USER",
    "PROMETHEUS_TOKEN",
    "FSPERF_USERNAME",
    "FSPERF_PASSWORD",
)


def placeholder_for(name: str) -> str:
    return f"placeholder-value-for-{name}"


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, input_text: str | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def git_show(repo_url: str, rev: str, path: str) -> str:
    cache_key = hashlib.sha256(f"{repo_url}@{rev}".encode()).hexdigest()[:16]
    dest = CACHE / cache_key
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        run(["git", "init", "-q"], cwd=dest)
        run(["git", "remote", "add", "origin", repo_url], cwd=dest)
    # Fetch the exact revision named by the workflow or action file.
    run(["git", "fetch", "--depth", "1", "origin", rev], cwd=dest)
    return run(["git", "show", "FETCH_HEAD:" + path], cwd=dest)


def materialize_repo(repo_url: str, rev: str) -> Path:
    cache_key = hashlib.sha256(f"tree:{repo_url}@{rev}".encode()).hexdigest()[:16]
    dest = CACHE / "trees" / cache_key
    if (dest / ".ready").exists():
        return dest
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    run(["git", "init", "-q"], cwd=dest)
    run(["git", "remote", "add", "origin", repo_url], cwd=dest)
    run(["git", "fetch", "--depth", "1", "origin", rev], cwd=dest)
    run(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=dest)
    (dest / ".ready").write_text(rev)
    return dest


def parse_uses(uses: str) -> dict:
    if uses.startswith("./") or uses.startswith(".\\") or uses.startswith("docker://"):
        return {"remote": False, "ref": "", "repo": "", "path": uses}
    pieces = uses.split("@")
    if len(pieces) != 2 or not pieces[0] or not pieces[1]:
        return {"remote": True, "ref": pieces[-1] if pieces else "", "repo": uses, "path": ""}
    left, ref = pieces
    segments = [segment for segment in left.split("/") if segment]
    repo = "/".join(segments[:2]) if len(segments) >= 2 else left
    path = "/".join(segments[2:]) if len(segments) > 2 else ""
    return {"remote": True, "ref": ref, "repo": repo, "path": path}


def is_full_sha(ref: str) -> bool:
    return bool(SHA_RE.fullmatch(ref))


def load_workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def effective_permissions(doc: dict, job: dict) -> dict:
    # WorkflowTemplateConverter copies root permissions onto a job only when
    # the job itself does not set permissions. PyYAML 1.1 parses the workflow
    # trigger key "on" as True, so ignore boolean keys.
    if job.get("permissions") is not None:
        return job.get("permissions") or {}
    root = doc.get("permissions")
    return root or {}


def id_token_write(permissions) -> bool:
    if permissions == "write-all":
        return True
    if isinstance(permissions, dict):
        return str(permissions.get("id-token", "")).lower() == "write"
    return False


def read_line(text: str, index: int) -> tuple[str | None, str | None, int]:
    """EnvFileKeyValuePairs.ReadLine for a Linux runner (LF newlines)."""
    if index >= len(text):
        return None, None, index
    lf_index = text.find("\n", index)
    if lf_index < 0:
        return text[index:], None, len(text)
    return text[index:lf_index], "\n", lf_index + 1


def parse_github_env(text: str) -> dict[str, str]:
    """Apply actions/runner SetEnvFileCommand's EnvFileKeyValuePairs parser."""
    pairs: dict[str, str] = {}
    index = 0
    line, _, index = read_line(text, index)
    while line is not None:
        if line != "":
            equals_index = line.find("=")
            heredoc_index = line.find("<<")
            if equals_index >= 0 and (heredoc_index < 0 or equals_index < heredoc_index):
                key, output = line.split("=", 1)
                if key == "":
                    raise ValueError(f"invalid env line {line!r}")
                pairs[key] = output
            elif heredoc_index >= 0 and (equals_index < 0 or heredoc_index < equals_index):
                key, delimiter = line.split("<<", 1)
                if key == "" or delimiter == "":
                    raise ValueError(f"invalid env heredoc {line!r}")
                start = index
                end = index
                temp, newline, index = read_line(text, index)
                while temp != delimiter:
                    if temp is None:
                        raise ValueError(f"missing env delimiter {delimiter!r}")
                    if newline is None:
                        raise ValueError("env delimiter missing newline")
                    end = index - len(newline)
                    temp, newline, index = read_line(text, index)
                pairs[key] = text[start:end] if end > start else ""
            else:
                raise ValueError(f"invalid env line {line!r}")
        line, _, index = read_line(text, index)
    return pairs


def action_yaml(repo: str, rev: str, action_path: str) -> dict:
    for name in ("action.yaml", "action.yml"):
        try:
            text = git_show(f"https://github.com/{repo}.git", rev, f"{action_path}/{name}")
        except AssertionError:
            continue
        return yaml.safe_load(text)
    raise AssertionError(f"no action file for {repo}/{action_path}@{rev}")


def vault_step_exports(action_doc: dict, workflow_step: dict) -> tuple[bool, str]:
    """Return whether this get-vault-secrets revision writes GITHUB_ENV, and the vault-action ref."""
    inputs = action_doc.get("inputs") or {}
    export_default = str((inputs.get("export_env") or {}).get("default", "true")).lower()
    step_with = workflow_step.get("with") or {}
    if "export_env" in step_with:
        chosen = str(step_with["export_env"]).lower()
    else:
        chosen = export_default
    vault_ref = ""
    for step in (action_doc.get("runs") or {}).get("steps") or []:
        uses = step.get("uses") or ""
        parsed = parse_uses(uses) if uses else None
        if not parsed or "hashicorp/vault-action" not in uses:
            continue
        vault_ref = parsed["ref"]
        flag = (step.get("with") or {}).get("exportEnv", "true")
        if isinstance(flag, bool):
            return flag, vault_ref
        flag_text = str(flag).strip()
        if flag_text.lower() == "false":
            return False, vault_ref
        if "inputs.export_env" in flag_text:
            return chosen != "false", vault_ref
        if flag_text.lower() == "true":
            return True, vault_ref
    return False, vault_ref


def ensure_vault_action(rev: str) -> Path:
    dest = materialize_repo("https://github.com/hashicorp/vault-action.git", rev)
    if not (dest / "node_modules" / "@actions" / "core").exists():
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=dest)
    return dest


EXPORT_DRIVER = r"""
const fs = require('fs');
const core = require('@actions/core');
const { parseSecretsInput } = require(process.env.ACTION_MODULE);

const exportEnv = core.getInput('exportEnv', { required: false }) != 'false';
const requests = parseSecretsInput(process.env.SECRETS_INPUT || '');
const placeholders = JSON.parse(process.env.PLACEHOLDERS_JSON || '{}');
for (const request of requests) {
  const value = placeholders[request.envVarName];
  if (value === undefined) {
    throw new Error('missing placeholder for ' + request.envVarName);
  }
  for (const line of String(value).replace(/\r/g, '').split('\n')) {
    if (line.length > 0) {
      core.setSecret(line);
    }
  }
  if (exportEnv) {
    core.exportVariable(request.envVarName, `${value}`);
  }
}
fs.writeFileSync(process.env.REQUESTS_OUT, JSON.stringify(requests.map((request) => request.envVarName)));
"""


def export_secrets(vault_dir: Path, translate_script: str, repo_secrets: str, export_env: bool) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        script = tmp_path / "translate-secrets.bash"
        script.write_text(translate_script)
        script.chmod(0o755)
        output = tmp_path / "github_output"
        output.write_text("")
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_OUTPUT": str(output),
                "REPO": "grafana/grafana",
                "REPO_SECRETS": repo_secrets,
                "COMMON_SECRETS": "",
            }
        )
        run(["bash", str(script)], env=env)
        secrets_input = parse_github_output_secret(output.read_text())
        requests = []
        # Names come from the real translate script. Placeholders are per name.
        for line in secrets_input.splitlines():
            if "|" not in line:
                continue
            name = line.split("|", 1)[1].strip().rstrip(";")
            if name:
                requests.append(name)
        placeholders = {name: placeholder_for(name) for name in requests}
        env_file = tmp_path / "github_env"
        env_file.write_text("")
        requests_out = tmp_path / "requests.json"
        driver = tmp_path / "export-driver.js"
        # The driver is executed with cwd at the vault-action revision so require()
        # loads that revision's parseSecretsInput and its locked @actions/core.
        driver.write_text(EXPORT_DRIVER)
        node_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "NODE_PATH": str(vault_dir / "node_modules"),
            "GITHUB_ENV": str(env_file),
            "INPUT_EXPORTENV": "true" if export_env else "false",
            "SECRETS_INPUT": secrets_input,
            "PLACEHOLDERS_JSON": json.dumps(placeholders),
            "REQUESTS_OUT": str(requests_out),
            "ACTION_MODULE": str(vault_dir / "src" / "action.js"),
        }
        run(["node", str(driver)], cwd=vault_dir, env=node_env)
        exported_names = json.loads(requests_out.read_text())
        parsed = parse_github_env(env_file.read_text())
        if export_env:
            missing = [name for name in exported_names if parsed.get(name) != placeholders[name]]
            if missing:
                raise AssertionError(f"GITHUB_ENV did not keep exported names {missing}")
        elif parsed:
            raise AssertionError(f"exportEnv false still wrote {sorted(parsed)}")
        return parsed


def parse_github_output_secret(text: str) -> str:
    """Read the multiline `secrets` output written by translate-secrets.bash."""
    parsed = parse_github_env(text)
    if "secrets" not in parsed:
        raise AssertionError("translate-secrets.bash did not write a secrets output")
    return parsed["secrets"]


PROBE_DRIVER = r"""
const fs = require('fs');
const { OidcClient } = require(process.env.OIDC_UTILS);
const names = JSON.parse(process.env.PROBE_NAMES);
const expected = JSON.parse(process.env.PROBE_EXPECTED);
const seen = [];
for (const name of names) {
  if (Object.prototype.hasOwnProperty.call(process.env, name) && process.env[name] === expected[name]) {
    seen.push(name);
  }
}
let oidc = false;
try {
  OidcClient.getRequestToken();
  OidcClient.getIDTokenUrl();
  oidc = true;
} catch (err) {
  oidc = false;
}
fs.writeFileSync(process.env.PROBE_RESULT, JSON.stringify({ seen, oidc }));
"""


def probe_step(environment: dict[str, str], names: list[str], oidc_utils: str, inject_oidc: bool) -> dict:
    """Spawn the step process the way ScriptHandler/NodeScriptActionHandler do."""
    with tempfile.TemporaryDirectory() as tmp:
        result_path = Path(tmp) / "probe.json"
        driver = Path(tmp) / "probe.js"
        driver.write_text(PROBE_DRIVER)
        expected = {name: environment[name] for name in names if name in environment}
        # Also tell the probe which placeholders would count if they were copied in.
        for name in names:
            expected.setdefault(name, placeholder_for(name))
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),
            "OIDC_UTILS": oidc_utils,
            "PROBE_NAMES": json.dumps(names),
            "PROBE_EXPECTED": json.dumps(expected),
            "PROBE_RESULT": str(result_path),
        }
        for key, value in environment.items():
            if key in env:
                continue
            env[key] = value
        if inject_oidc:
            # Job-scoped OIDC endpoint. Handlers copy it into every step; they do
            # not check the action ref. These values are placeholders.
            env["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.example.invalid/token"
            env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "placeholder-oidc-request-token"
        run(["node", str(driver)], env=env)
        return json.loads(result_path.read_text())


def iter_jobs(doc: dict):
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return
    for name, job in jobs.items():
        if isinstance(job, dict) and job.get("steps"):
            yield name, job


def scan_workflows() -> list[str]:
    findings: list[str] = []
    vault_dirs: dict[str, Path] = {}
    oidc_utils = ""

    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        doc = load_workflow(path)
        for job_name, job in iter_jobs(doc):
            permissions = effective_permissions(doc, job)
            inject_oidc = id_token_write(permissions)
            job_env: dict[str, str] = {}
            exported_names: list[str] = []
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses") or ""
                parsed = parse_uses(uses) if uses else None
                # The ref is read at this step, which is when the runner resolves it.
                if (
                    parsed
                    and parsed["remote"]
                    and not is_full_sha(parsed["ref"])
                    and exported_names
                ):
                    if not oidc_utils:
                        raise AssertionError("OIDC client path was not prepared")
                    report = probe_step(job_env, exported_names, oidc_utils, inject_oidc)
                    if report["seen"] or report["oidc"]:
                        label = step.get("name") or step.get("id") or f"step {index}"
                        findings.append(
                            f"{path.relative_to(REPO_ROOT)} job {job_name} step {label} "
                            f"uses {uses}: process saw vault env {report['seen']} "
                            f"oidc_request={report['oidc']}"
                        )
                if parsed and "get-vault-secrets" in uses and parsed["remote"]:
                    action = action_yaml(parsed["repo"], parsed["ref"], parsed["path"])
                    exports, vault_ref = vault_step_exports(action, step)
                    later_mutable = False
                    for later in (job.get("steps") or [])[index + 1 :]:
                        later_uses = later.get("uses") if isinstance(later, dict) else ""
                        if not later_uses:
                            continue
                        later_parsed = parse_uses(later_uses)
                        if later_parsed["remote"] and not is_full_sha(later_parsed["ref"]):
                            later_mutable = True
                            break
                    # Only a later moving-ref action observes this export. Jobs that
                    # export and then run only pinned actions or shell steps do not
                    # share this bug.
                    if not exports or not later_mutable:
                        continue
                    if not is_full_sha(vault_ref):
                        raise AssertionError(f"vault-action ref {vault_ref} is not a commit")
                    if vault_ref not in vault_dirs:
                        vault_dirs[vault_ref] = ensure_vault_action(vault_ref)
                    vault_dir = vault_dirs[vault_ref]
                    oidc_utils = str(vault_dir / "node_modules" / "@actions" / "core" / "lib" / "oidc-utils.js")
                    translate = git_show(
                        f"https://github.com/{parsed['repo']}.git",
                        parsed["ref"],
                        f"{parsed['path']}/translate-secrets.bash",
                    )
                    repo_secrets = str((step.get("with") or {}).get("repo_secrets") or "")
                    exported = export_secrets(vault_dir, translate, repo_secrets, True)
                    # Runner ProcessFiles applies GITHUB_ENV after the step returns,
                    # so only later steps inherit it.
                    job_env.update(exported)
                    exported_names = list(exported.keys())

            if path.name == PERFORMANCE_WORKFLOW and job_name == "performance-tests":
                login_steps = [
                    step
                    for step in job.get("steps") or []
                    if isinstance(step, dict) and "login-to-gar@" in (step.get("uses") or "")
                ]
                if not login_steps:
                    findings.append(
                        f"{path.relative_to(REPO_ROOT)} job {job_name} has no login-to-gar step"
                    )
                for step in login_steps:
                    ref = parse_uses(step["uses"])["ref"]
                    if not is_full_sha(ref):
                        findings.append(
                            f"{path.relative_to(REPO_ROOT)} job {job_name} login-to-gar ref {ref!r} "
                            "is not a full commit SHA"
                        )
    return findings


class UnpinnedLoginAfterVaultTests(unittest.TestCase):
    def test_env_file_round_trip_uses_actions_core_and_runner_parser(self):
        vault_dir = ensure_vault_action("4c06c5ccf5c0761b6029f56cfb1dcf5565918a3b")
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "github_env"
            env_file.write_text("")
            driver = Path(tmp) / "export.js"
            driver.write_text(
                "const core = require('@actions/core');\n"
                "core.exportVariable(process.env.NAME, process.env.VALUE);\n"
            )
            name = "FSPERF_PASSWORD"
            value = placeholder_for(name)
            run(
                ["node", str(driver)],
                cwd=vault_dir,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", "/tmp"),
                    "NODE_PATH": str(vault_dir / "node_modules"),
                    "GITHUB_ENV": str(env_file),
                    "NAME": name,
                    "VALUE": value,
                },
            )
            parsed = parse_github_env(env_file.read_text())
        self.assertEqual(parsed.get(name), value)

    def test_mutable_action_after_vault_export_cannot_read_secrets_or_oidc(self):
        findings = scan_workflows()
        self.assertEqual(
            findings,
            [],
            "moving-ref actions can read Vault-exported job environment or the job OIDC request:\n"
            + "\n".join(findings),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
