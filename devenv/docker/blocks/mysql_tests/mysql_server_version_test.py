#!/usr/bin/env python3
"""Fail while a Grafana dev or CI MySQL server is an affected InnoDB build.

Each case starts the server through the repository file that selects its
image, then reads the version from the MySQL handshake on the published port
and from the running server. The case fails when that version is inside the
affected ranges, or when the process that came up is not the pinned server
with InnoDB as its default engine.

The ranges are the MySQL Server / InnoDB rows of the October 2025 Oracle CPU:
8.0.0-8.0.43, 8.4.0-8.4.6, and 9.0.0-9.4.0, upper bounds included.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DEVENV = ROOT / "devenv"
PLACEHOLDER_PASSWORD = "placeholder"

# Inclusive upper bounds from the October 2025 Oracle CPU MySQL Server InnoDB row.
AFFECTED = (
    ((8, 0, 0), (8, 0, 43)),
    ((8, 4, 0), (8, 4, 6)),
    ((9, 0, 0), (9, 4, 0)),
)

FAILURES = []


def fail(message):
    FAILURES.append(message)
    print(f"FAIL {message}")


def ok(message):
    print(f"PASS {message}")


def parse_version(text):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def version_affected(text):
    parsed = parse_version(text)
    if parsed is None:
        return False
    for lower, upper in AFFECTED:
        if lower <= parsed <= upper:
            return True
    return False


def check_range_table():
    samples = {
        "8.0.0": True,
        "8.0.43": True,
        "8.0.44": False,
        "8.3.0": False,
        "8.4.0": True,
        "8.4.6": True,
        "8.4.7": False,
        "9.0.0": True,
        "9.3.2": True,
        "9.4.0": True,
        "9.4.1": False,
        "9.7.4": False,
        "26.10.0": False,
    }
    bad = [ver for ver, affected in samples.items() if version_affected(ver) != affected]
    if bad:
        fail(f"affected-range table disagrees with the CPU bounds for {bad}")
    else:
        ok("affected-range table matches the CPU bounds")


def run(cmd, cwd, env=None, timeout=600):
    merged = os.environ.copy()
    merged.pop("mysql_version", None)
    if env:
        merged.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def redact(text):
    # Compose and registry errors can echo credentials or signed URLs.
    redacted = re.sub(r"https?://\S+", "<url>", text or "")
    redacted = re.sub(
        r"(?i)(password|passwd|pwd)([^\s=]*)\s*[:=]\s*\S+",
        r"\1\2=<redacted>",
        redacted,
    )
    return redacted[-1500:]


def docker(*args, cwd=ROOT, timeout=600):
    return run(["docker", *args], cwd=cwd, timeout=timeout)


def pull_official_mysql(tag):
    """Pull mysql:<tag> for the FROM and image lines in this repository.

    A failed Docker Hub pull is retried from public.ecr.aws/docker/library/mysql
    and tagged back to mysql:<tag>. That image's history installs
    mysql-community-server-minimal for the same version.
    """
    direct = docker("pull", f"mysql:{tag}", timeout=900)
    if direct.returncode == 0:
        return True
    mirror = f"public.ecr.aws/docker/library/mysql:{tag}"
    mirrored = docker("pull", mirror, timeout=900)
    if mirrored.returncode != 0:
        return False
    tagged = docker("tag", mirror, f"mysql:{tag}", timeout=30)
    return tagged.returncode == 0


def down_everything():
    compose_files = [
        DEVENV / "docker-compose.yaml",
        DEVENV / "docker" / "ha_test" / "docker-compose.yaml",
        DEVENV / "docker" / "ha-test-unified-alerting" / "docker-compose.yaml",
    ]
    for path in compose_files:
        if path.exists():
            docker("compose", "-f", str(path), "down", "--remove-orphans", timeout=180)
    docker(
        "rm",
        "-f",
        "mysql-cve-arg-default",
        "mysql-cve-opendata",
        "mysql-cve-bitnami",
        timeout=60,
    )


def published_port(container_id):
    result = docker("port", container_id, "3306/tcp", timeout=20)
    ports = []
    for line in result.stdout.splitlines():
        match = re.search(r":(\d+)\s*$", line.strip())
        if match:
            ports.append(int(match.group(1)))
    return ports[0] if ports else None


def wait_for_greeting(port, timeout_s=120):
    deadline = time.time() + timeout_s
    last_error = "no connection"
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2) as sock:
                sock.settimeout(2)
                packet = sock.recv(128)
            if len(packet) >= 6 and packet[4] == 10:
                end = packet.find(b"\x00", 5)
                if end > 5:
                    return packet[5:end].decode("ascii", "replace")
            last_error = f"unexpected greeting bytes {packet[:8]!r}"
        except OSError as exc:
            last_error = str(exc)
        time.sleep(1)
    return f"ERROR {last_error}"


def query_server(container_id):
    command = (
        'mysql --protocol=socket -uroot -p"$MYSQL_ROOT_PASSWORD" '
        "--batch --skip-column-names --silent "
        '-e "SELECT VERSION(); SELECT @@default_storage_engine; '
        "SELECT SUPPORT FROM information_schema.ENGINES WHERE ENGINE='InnoDB';\""
    )
    result = docker("exec", container_id, "sh", "-c", command, timeout=30)
    if result.returncode != 0:
        # Bitnami and some entrypoints use a different root password variable.
        command = (
            'mysql --protocol=socket -uroot -p"$MYSQL_ROOT_PASSWORD" '
            "--batch --skip-column-names --silent "
            '-e "SELECT VERSION(); SELECT @@default_storage_engine; '
            "SELECT SUPPORT FROM information_schema.ENGINES WHERE ENGINE='InnoDB';\""
        )
        alt = (
            'pw="$MYSQL_ROOT_PASSWORD"; '
            'if [ -z "$pw" ]; then pw="$MARIADB_ROOT_PASSWORD"; fi; '
            'mysql --protocol=socket -uroot -p"$pw" --batch --skip-column-names --silent '
            '-e "SELECT VERSION(); SELECT @@default_storage_engine; '
            "SELECT SUPPORT FROM information_schema.ENGINES WHERE ENGINE='InnoDB';\""
        )
        result = docker("exec", container_id, "sh", "-c", alt, timeout=30)
    if result.returncode != 0:
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip() and "insecure" not in line.lower()]
    return lines


def process_args(container_id):
    result = docker("top", container_id, timeout=20)
    if result.returncode != 0:
        return ""
    return result.stdout


def assert_server(label, container_id, pinned, required_arg):
    port = published_port(container_id)
    if port is None:
        fail(f"{label}: container does not publish MySQL port 3306")
        return
    greeting = wait_for_greeting(port)
    if greeting.startswith("ERROR"):
        fail(f"{label}: published port {port} did not speak MySQL ({greeting})")
        return
    rows = None
    deadline = time.time() + 60
    while time.time() < deadline:
        rows = query_server(container_id)
        if rows and len(rows) >= 3:
            break
        time.sleep(2)
    if not rows or len(rows) < 3:
        fail(f"{label}: running server did not report version and InnoDB status")
        return
    version, engine, support = rows[0], rows[1], rows[2]
    print(f"INFO {label}: greeting={greeting} version={version} engine={engine} innodb={support}")
    if parse_version(greeting) != parse_version(version):
        fail(f"{label}: handshake version {greeting} is not the server version {version}")
    if parse_version(version) != parse_version(pinned):
        fail(f"{label}: running version {version} is not the pinned version {pinned}")
    if engine != "InnoDB" or support not in {"DEFAULT", "YES"}:
        fail(f"{label}: InnoDB is not the active default engine (engine={engine}, support={support})")
    args = process_args(container_id)
    if "mysqld" not in args:
        fail(f"{label}: container process is not mysqld")
    elif required_arg and required_arg not in args:
        fail(f"{label}: mysqld was not started with {required_arg}")
    if version_affected(version):
        fail(
            f"{label}: MySQL {version} is inside the affected InnoDB ranges "
            f"and is the server listening on port {port}"
        )
    else:
        ok(f"{label}: MySQL {version} is outside the affected InnoDB ranges")


def workflow_pins():
    path = ROOT / ".github" / "workflows" / "pr-test-integration.yml"
    job = None
    found = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if job_match:
            job = job_match.group(1)
        pin = re.search(r"make devenv sources=mysql_tests mysql_version=(\d+\.\d+\.\d+)\s*$", line.strip())
        if pin:
            found.append((job, number, pin.group(1)))
    jobs = {item[0] for item in found}
    if jobs != {"mysql", "mysql-enterprise"} or len(found) != 2:
        fail(f"workflow MySQL jobs: expected mysql and mysql-enterprise pins, found {found}")
    else:
        ok(f"workflow pins both MySQL jobs: {found}")
    return found


def launch_make(sources, version):
    cmd = ["make", "devenv", f"sources={sources}"]
    env = {}
    if version is not None:
        cmd.append(f"mysql_version={version}")
        env["mysql_version"] = version
    result = run(cmd, ROOT, env=env, timeout=900)
    if result.returncode != 0:
        print(f"INFO make devenv sources={sources} exited {result.returncode}")
        print(redact(result.stdout + "\n" + result.stderr))
    return result.returncode


def service_id(service):
    result = docker("compose", "ps", "-q", service, cwd=DEVENV, timeout=30)
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return ids[0] if ids else ""


def check_make_block(label, sources, service, version, required_arg):
    down_everything()
    pinned_tag = version
    if pinned_tag is None:
        env_file = DEVENV / "docker" / "blocks" / sources / ".env"
        match = re.search(r"^mysql_version=(\d+\.\d+\.\d+)\s*$", env_file.read_text(), re.M)
        pinned_tag = match.group(1) if match else None
    if pinned_tag and not pull_official_mysql(pinned_tag):
        fail(f"{label}: could not pull the official mysql:{pinned_tag} image")
        return
    launch_make(sources, version)
    container_id = service_id(service)
    if not container_id:
        # make devenv starts every service in the block. A non-server sidecar
        # can abort that before mysqld is up. Start the MySQL service from the
        # compose file the Makefile just generated.
        started = docker(
            "compose",
            "up",
            "-d",
            "--no-deps",
            "--pull",
            "never",
            service,
            cwd=DEVENV,
            timeout=300,
        )
        if started.returncode != 0:
            print(redact(started.stdout + "\n" + started.stderr))
        container_id = service_id(service)
    if not container_id:
        fail(f"{label}: make devenv sources={sources} did not leave service {service} running")
        return
    pinned = version
    if pinned is None:
        env_file = DEVENV / "docker" / "blocks" / sources / ".env"
        match = re.search(r"^mysql_version=(\d+\.\d+\.\d+)\s*$", env_file.read_text(), re.M)
        if not match:
            fail(f"{label}: {env_file} has no mysql_version pin")
            return
        pinned = match.group(1)
    assert_server(label, container_id, pinned, required_arg)


def check_compose_db(label, compose_path, pinned, required_arg):
    down_everything()
    if not pull_official_mysql(pinned):
        fail(f"{label}: could not pull the official mysql:{pinned} image")
        return
    result = docker(
        "compose",
        "-f",
        str(compose_path),
        "up",
        "-d",
        "--no-deps",
        "db",
        cwd=compose_path.parent,
        timeout=900,
    )
    if result.returncode != 0:
        fail(f"{label}: compose up db failed")
        print(redact(result.stdout + "\n" + result.stderr))
        return
    ident = docker("compose", "-f", str(compose_path), "ps", "-q", "db", cwd=compose_path.parent, timeout=30)
    container_id = ident.stdout.strip().splitlines()[0] if ident.stdout.strip() else ""
    if not container_id:
        fail(f"{label}: db container was not created")
        return
    assert_server(label, container_id, pinned, required_arg)


def env_file_from_tests_compose():
    text = (DEVENV / "docker" / "blocks" / "mysql_tests" / "docker-compose.yaml").read_text()
    env_lines = []
    in_env = False
    for line in text.splitlines():
        if re.match(r"\s+environment:\s*$", line):
            in_env = True
            continue
        if in_env:
            match = re.match(r"\s+([A-Z0-9_]+):\s*(\S+)\s*$", line)
            if not match:
                break
            env_lines.append(f"{match.group(1)}={match.group(2)}")
    command = re.findall(r'"([^"]+)"', text.split("command:", 1)[1].split("environment:", 1)[0])
    return env_lines, command


def check_dockerfile_default():
    label = "mysql_tests Dockerfile ARG default"
    dockerfile = DEVENV / "docker" / "blocks" / "mysql_tests" / "Dockerfile"
    match = re.search(r"^ARG mysql_version=(\d+\.\d+\.\d+)\s*$", dockerfile.read_text(), re.M)
    if not match:
        fail(f"{label}: ARG mysql_version default is missing")
        return
    pinned = match.group(1)
    down_everything()
    if not pull_official_mysql(pinned):
        fail(f"{label}: could not pull the official mysql:{pinned} image")
        return
    built = docker(
        "build",
        "--pull",
        "-t",
        "mysql-cve-arg-default",
        str(DEVENV / "docker" / "blocks" / "mysql_tests"),
        timeout=900,
    )
    if built.returncode != 0:
        fail(f"{label}: docker build without a version build-arg failed")
        print(redact(built.stdout + "\n" + built.stderr))
        return
    env_lines, command = env_file_from_tests_compose()
    if not command or command[0] != "mysqld":
        fail(f"{label}: could not read the mysqld command from the compose file")
        return
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("\n".join(env_lines) + "\n")
        env_path = handle.name
    os.chmod(env_path, 0o600)
    try:
        started = docker(
            "run",
            "-d",
            "--name",
            "mysql-cve-arg-default",
            "-p",
            "3306:3306",
            "--env-file",
            env_path,
            "mysql-cve-arg-default",
            *command,
            timeout=120,
        )
    finally:
        os.remove(env_path)
    if started.returncode != 0:
        fail(f"{label}: container did not start")
        print(redact(started.stdout + "\n" + started.stderr))
        return
    container_id = started.stdout.strip()
    assert_server(label, container_id, pinned, command[1] if len(command) > 1 else "")


def image_from_dockerfile(path):
    match = re.search(r"^FROM\s+(\S+)", path.read_text(), re.M)
    return match.group(1) if match else ""


def check_official_image(label, image, name):
    tag = image.rsplit(":", 1)[-1]
    down_everything()
    if not pull_official_mysql(tag):
        fail(f"{label}: could not pull the official mysql:{tag} image")
        return
    started = docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "3306:3306",
        "-e",
        f"MYSQL_ROOT_PASSWORD={PLACEHOLDER_PASSWORD}",
        "-e",
        "MYSQL_DATABASE=grafana_tests",
        image,
        timeout=120,
    )
    if started.returncode != 0:
        fail(f"{label}: container did not start")
        print(redact(started.stdout + "\n" + started.stderr))
        return
    pinned = image.rsplit(":", 1)[-1]
    container_id = started.stdout.strip()
    # A floating tag has no numeric pin. The running server version is the pin.
    if parse_version(pinned) is None:
        port = published_port(container_id)
        greeting = wait_for_greeting(port) if port else "ERROR no published port"
        if greeting.startswith("ERROR"):
            fail(f"{label}: could not read the running version ({greeting})")
            return
        pinned = greeting
    assert_server(label, container_id, pinned, "")


def check_bitnami_readme():
    label = "unified storage README bitnami MySQL"
    text = (ROOT / "pkg" / "storage" / "unified" / "README.md").read_text()
    match = re.search(r"docker\.io/bitnami/mysql:(\d+\.\d+\.\d+)", text)
    if not match:
        fail(f"{label}: image pin not found")
        return
    pinned = match.group(1)
    image = f"docker.io/bitnami/mysql:{pinned}"
    down_everything()
    pulled = docker("pull", image, timeout=900)
    if pulled.returncode != 0:
        print(f"SKIP {label}: registry did not provide {image}")
        return
    started = docker(
        "run",
        "-d",
        "--name",
        "mysql-cve-bitnami",
        "-p",
        "3306:3306",
        "-e",
        f"MYSQL_ROOT_PASSWORD={PLACEHOLDER_PASSWORD}",
        "-e",
        "MYSQL_DATABASE=grafana_tests",
        image,
        timeout=120,
    )
    if started.returncode != 0:
        fail(f"{label}: container did not start")
        print(redact(started.stdout + "\n" + started.stderr))
        return
    assert_server(label, started.stdout.strip(), pinned, "")


def main():
    if shutil.which("docker") is None:
        print("FAIL docker is not installed")
        return 1
    check_range_table()
    pins = workflow_pins()
    seen = set()
    for job, number, version in pins:
        if version in seen:
            continue
        seen.add(version)
        lines = ",".join(str(item[1]) for item in pins if item[2] == version)
        check_make_block(
            f"CI mysql_tests workflow lines {lines}",
            "mysql_tests",
            "mysqltests",
            version,
            "--innodb-flush-log-at-trx-commit=0",
        )
    check_make_block(
        "local make devenv sources=mysql_tests",
        "mysql_tests",
        "mysqltests",
        None,
        "--innodb-flush-log-at-trx-commit=0",
    )
    check_make_block(
        "local make devenv sources=mysql",
        "mysql",
        "mysql",
        None,
        "--innodb_monitor_enable=all",
    )
    for label, path in (
        ("ha_test db", DEVENV / "docker" / "ha_test" / "docker-compose.yaml"),
        (
            "ha-test-unified-alerting db",
            DEVENV / "docker" / "ha-test-unified-alerting" / "docker-compose.yaml",
        ),
    ):
        match = re.search(r"image:\s*mysql:(\d+\.\d+\.\d+)", path.read_text())
        if not match:
            fail(f"{label}: mysql image pin not found")
            continue
        check_compose_db(label, path, match.group(1), "--innodb_monitor_enable=all")
    check_dockerfile_default()
    opendata = image_from_dockerfile(DEVENV / "docker" / "blocks" / "mysql_opendata" / "Dockerfile")
    if not opendata.startswith("mysql:"):
        fail(f"mysql_opendata base image is {opendata or 'missing'}")
    else:
        check_official_image(f"mysql_opendata base {opendata}", opendata, "mysql-cve-opendata")
    check_bitnami_readme()
    down_everything()
    if FAILURES:
        print(f"{len(FAILURES)} failure(s)")
        return 1
    print("all MySQL server pins are outside the affected InnoDB ranges")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        down_everything()
